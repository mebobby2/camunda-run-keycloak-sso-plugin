/*
 * Camunda Platform REST API
 * OpenApi Spec for Camunda Platform REST API.
 *
 * The version of the OpenAPI document: 7.16.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.camunda.consulting.openapi.client.model;

import java.util.Objects;
import java.util.Arrays;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * DecisionRequirementsDefinitionXmlDto
 */
@JsonPropertyOrder({
  DecisionRequirementsDefinitionXmlDto.JSON_PROPERTY_ID,
  DecisionRequirementsDefinitionXmlDto.JSON_PROPERTY_DMN_XML
})
@JsonTypeName("DecisionRequirementsDefinitionXmlDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class DecisionRequirementsDefinitionXmlDto {
  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_DMN_XML = "dmnXml";
  private String dmnXml;


  public DecisionRequirementsDefinitionXmlDto id(String id) {
    
    this.id = id;
    return this;
  }

   /**
   * The id of the decision requirements definition.
   * @return id
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the decision requirements definition.")
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getId() {
    return id;
  }


  public void setId(String id) {
    this.id = id;
  }


  public DecisionRequirementsDefinitionXmlDto dmnXml(String dmnXml) {
    
    this.dmnXml = dmnXml;
    return this;
  }

   /**
   * An escaped XML string containing the XML that this decision requirements definition was deployed with. Carriage returns, line feeds and quotation marks are escaped.
   * @return dmnXml
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An escaped XML string containing the XML that this decision requirements definition was deployed with. Carriage returns, line feeds and quotation marks are escaped.")
  @JsonProperty(JSON_PROPERTY_DMN_XML)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getDmnXml() {
    return dmnXml;
  }


  public void setDmnXml(String dmnXml) {
    this.dmnXml = dmnXml;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DecisionRequirementsDefinitionXmlDto decisionRequirementsDefinitionXmlDto = (DecisionRequirementsDefinitionXmlDto) o;
    return Objects.equals(this.id, decisionRequirementsDefinitionXmlDto.id) &&
        Objects.equals(this.dmnXml, decisionRequirementsDefinitionXmlDto.dmnXml);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, dmnXml);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DecisionRequirementsDefinitionXmlDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    dmnXml: ").append(toIndentedString(dmnXml)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}

