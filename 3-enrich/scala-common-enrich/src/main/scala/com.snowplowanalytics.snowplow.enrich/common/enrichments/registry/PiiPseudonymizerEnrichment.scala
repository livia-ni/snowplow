/*
 * Copyright (c) 2017-2018 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */

package com.snowplowanalytics
package snowplow.enrich
package common.enrichments.registry

//Scala
import com.snowplowanalytics.snowplow.enrich.common.ValidatedMessage
import org.json4s.JValue

import scala.collection.JavaConverters._

//Snowplow
import com.fasterxml.jackson.databind.node.ArrayNode
import com.jayway.jsonpath.MapFunction
import iglu.client.{SchemaCriterion, SchemaKey}
import common.{Validated,            ValidatedNelMessage}
import common.utils.MapTransformer.TransformMap
import common.utils.ScalazJson4sUtils

//Scala libraries
import org.json4s.JsonAST._
import org.json4s.jackson.JsonMethods
import org.json4s.jackson.JsonMethods.{compact, parse, render}

//Java
import java.security.{MessageDigest, NoSuchAlgorithmException}
import org.apache.maven.artifact.versioning.DefaultArtifactVersion
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.{ObjectNode, TextNode}
import com.github.fge.jsonschema.core.report.ProcessingMessage
import com.jayway.jsonpath.spi.json.JacksonJsonNodeJsonProvider
import com.jayway.jsonpath.{Configuration, JsonPath => JJsonPath, Option => JOption}

//scalaz
import scalaz.Scalaz._
import scalaz._

/**
 * PiiField trait. This corresponds to a configuration top-level field (i.e. either a POJO or a JSON field) along with
 * a function to apply that strategy to a TransformMap
 */
trait PiiField {
  val strategy: PiiStrategy
  val fieldName: String
  def transformer(transformMap: TransformMap): TransformMap
  def applyStrategy(fieldValue: String): String
}

/**
 * PiiStrategy trait. This corresponds to a strategy to apply to a single field. Currently only only String input is
 * supported.
 */
trait PiiStrategy {
  def scramble: String => String
}

/**
 * Companion object. Lets us create a PiiPseudonymizerEnrichment
 * from a JValue.
 */
object PiiPseudonymizerEnrichment extends ParseableEnrichment {
  val supportedSchema = SchemaCriterion("com.snowplowanalytics.snowplow.enrichments", "pii_pseudonymizer_config", "jsonscehma", 1, 0, 0)

  def parse(config: JValue, schemaKey: SchemaKey): ValidatedNelMessage[PiiPseudonymizerEnrichment] = {
    for {
      conf      <- matchesSchema(config, schemaKey)
      piiFields <- ScalazJson4sUtils.extract[List[JObject]](conf, "parameters", "pii").leftMap(_.getMessage)
      strategyFunction <- ScalazJson4sUtils
        .extract[String](config, "parameters", "strategy", "pseudonymize", "hashFunction")
        .leftMap(_.getMessage)
      hashFunction <- try {
        MessageDigest.getInstance(strategyFunction).success
      } catch {
        case e: NoSuchAlgorithmException =>
          s"Could not parse PII enrichment config: ${e.getMessage()}".fail
      }
      strategy = PiiStrategyPseudonymize(hashFunction)
      piiFieldList <- piiFields.map {
        case JObject(List(("pojo", JObject(List(("field", JString(fieldName))))))) =>
          PiiPojo(strategy, fieldName).success
        case JObject(
            List(
              ("json",
               JObject(
                 List(("field", JString(fieldName)), ("schemaCriterion", JString(schemaCriterion)), ("jsonPath", JString(jsonPath))))))) =>
          SchemaCriterion
            .parse(schemaCriterion)
            .flatMap { sc =>
              PiiJson(strategy, fieldName, sc, jsonPath).success
            }
            .leftMap(_.getMessage)
      }.sequenceU
    } yield PiiPseudonymizerEnrichment(piiFieldList)
  }.leftMap(getProcessingMessage(_)).toValidationNel

  private def getProcessingMessage(s: String): ProcessingMessage = {
    val pm = new ProcessingMessage()
    pm.setMessage(s)
    pm
  }

  private def matchesSchema(config: JValue, schemaKey: SchemaKey): Validation[String, JValue] =
    if (supportedSchema matches schemaKey) {
      config.success
    } else {
      ("Schema key %s is not supported. A '%s' enrichment must have schema '%s'.")
        .format(schemaKey, supportedSchema.name, supportedSchema)
        .fail
    }
}

/**
 * The PiiPseudonymizerEnrichment runs after all other enrichments to find fields that are configured as PII and apply
 * some anonymization (currently only psudonymizantion) on them. Currently a single strategy for all the fields is
 * supported due to the config format, and there being only one implemented strategy, however the enrichment supports a
 * strategy per field configured.
 *
 * The user may specify two types of fields POJO or JSON. A POJO field is effectively a scalar field in the
 * EnrichedEvent, whereas a JSON is a "context" formatted field (a JSON string in "contexts" field in enriched event)
 *
 * @param fieldList a lits of configured PiiFields
 */
case class PiiPseudonymizerEnrichment(fieldList: List[PiiField]) extends Enrichment {
  override val version: DefaultArtifactVersion = new DefaultArtifactVersion("99999.66666.33333")
  def transformer(transformMap: TransformMap)  = transformMap ++ fieldList.map(_.transformer(transformMap)).reduce(_ ++ _)
}

/**
 * Specifies a field in POJO and the trategy that should be applied to it.
 * @param strategy
 * @param fieldName
 */
case class PiiPojo(strategy: PiiStrategy, fieldName: String) extends PiiField {
  override def transformer(transformMap: TransformMap): TransformMap =
    transformMap.collect({
      case (inputField: String, (tf: Function2[String, String, Validation[String, String]], outputField: String))
          if (outputField == fieldName) =>
        (inputField,
         ((arg1: String, arg2: String) => tf.tupled.andThen(_.flatMap({ case s: String => applyStrategy(s).success }))((arg1, arg2)),
          outputField))
    })

  override def applyStrategy(fieldValue: String): String = strategy.scramble(fieldValue)
}

/**
 * Specifies a strategy to use, a field (should be "contexts") where teh JSON can be found, a schema criterion to
 * discriminate which contexts to apply this strategy to, and a json path within the contexts where this strategy will
 * be apllied (the path may correspond to multiple fields).
 *
 * @param strategy
 * @param fieldName
 * @param schemaCriterion
 * @param jsonPath
 */
case class PiiJson(strategy: PiiStrategy, fieldName: String, schemaCriterion: SchemaCriterion, jsonPath: String) extends PiiField {
  override def transformer(transformMap: TransformMap): TransformMap =
    transformMap.collect({
      case (inputField: String, (tf: Function2[String, String, Validation[String, String]], outputField: String))
          if (outputField == fieldName) =>
        (inputField,
         ((arg1: String, arg2: String) => tf.tupled.andThen(_.flatMap({ case s: String => applyStrategy(s).success }))((arg1, arg2)),
          outputField))
    })

  override def applyStrategy(fieldValue: String): String = {
    val jv = parse(fieldValue)
    val jv1 = jv.transformField {
      case JField("data", contents) =>
        ("data", contents.transform {
          case ja: JArray => {
            ja.transform {
              case JObject(List(("schema", JString(schema)), ("data", jobject)))
                  if (SchemaKey.parse(schema).flatMap(schemaCriterion.matches(_).success).getOrElse(false)) => {
                JObject(List(("schema", JString(schema)), ("data", JSPathReplace(jobject))))
              }
            }
          }
        })
    }
    compact(render(jv1))
  }
  //Configuration for JsonPath
  private val jsonPathConf =
    Configuration.builder().options(JOption.SUPPRESS_EXCEPTIONS).jsonProvider(new JacksonJsonNodeJsonProvider()).build()

  /**
   * Replaces a value in the given context data with the result of applying teh strategy that value.
   *
   * @param jValue
   * @return the modified jValue
   */
  def JSPathReplace(jValue: JValue): JValue = {
    val sth = JsonMethods.mapper.valueToTree[ObjectNode](jValue)
    val inp = JJsonPath.using(jsonPathConf).parse(sth)
    inp.map(
      jsonPath,
      new MapFunction {
        override def map(currentValue: scala.Any, configuration: Configuration): AnyRef = currentValue match {
          case s: String => strategy.scramble(s)
          case a: ArrayNode =>
            a.elements.asScala.map {
              case t: TextNode     => strategy.scramble(t.asText())
              case default: AnyRef => default
            }
          case default: AnyRef => default
        }
      }
    )
    JsonMethods.fromJsonNode(inp.json[JsonNode]())
  }
}

/**
 * Implements a pseudonymization strategy using any algorithm known to MessageDigest
 * @param hashFunction
 */
case class PiiStrategyPseudonymize(hashFunction: MessageDigest) extends PiiStrategy {
  override def scramble          = (clearText: String) => hash(clearText)
  def hash(text: String): String = String.format("%064x", new java.math.BigInteger(1, hashFunction.digest(text.getBytes("UTF-8"))))
}
