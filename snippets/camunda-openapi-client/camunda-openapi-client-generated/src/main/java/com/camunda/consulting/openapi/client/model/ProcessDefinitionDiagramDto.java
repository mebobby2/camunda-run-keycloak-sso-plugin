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
 * ProcessDefinitionDiagramDto
 */
@JsonPropertyOrder({
  ProcessDefinitionDiagramDto.JSON_PROPERTY_ID,
  ProcessDefinitionDiagramDto.JSON_PROPERTY_BPMN20_XML
})
@JsonTypeName("ProcessDefinitionDiagramDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class ProcessDefinitionDiagramDto {
  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_BPMN20_XML = "bpmn20Xml";
  private String bpmn20Xml;


  public ProcessDefinitionDiagramDto id(String id) {
    
    this.id = id;
    return this;
  }

   /**
   * The id of the process definition.
   * @return id
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the process definition.")
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getId() {
    return id;
  }


  public void setId(String id) {
    this.id = id;
  }


  public ProcessDefinitionDiagramDto bpmn20Xml(String bpmn20Xml) {
    
    this.bpmn20Xml = bpmn20Xml;
    return this;
  }

   /**
   * An escaped XML string containing the XML that this definition was deployed with. Carriage returns, line feeds and quotation marks are escaped.
   * @return bpmn20Xml
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An escaped XML string containing the XML that this definition was deployed with. Carriage returns, line feeds and quotation marks are escaped.")
  @JsonProperty(JSON_PROPERTY_BPMN20_XML)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getBpmn20Xml() {
    return bpmn20Xml;
  }


  public void setBpmn20Xml(String bpmn20Xml) {
    this.bpmn20Xml = bpmn20Xml;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ProcessDefinitionDiagramDto processDefinitionDiagramDto = (ProcessDefinitionDiagramDto) o;
    return Objects.equals(this.id, processDefinitionDiagramDto.id) &&
        Objects.equals(this.bpmn20Xml, processDefinitionDiagramDto.bpmn20Xml);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, bpmn20Xml);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ProcessDefinitionDiagramDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    bpmn20Xml: ").append(toIndentedString(bpmn20Xml)).append("\n");
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

