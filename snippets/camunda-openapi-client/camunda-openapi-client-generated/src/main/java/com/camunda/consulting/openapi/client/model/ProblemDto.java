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
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * ProblemDto
 */
@JsonPropertyOrder({
  ProblemDto.JSON_PROPERTY_MESSAGE,
  ProblemDto.JSON_PROPERTY_LINE,
  ProblemDto.JSON_PROPERTY_COLUMN,
  ProblemDto.JSON_PROPERTY_MAIN_ELEMENT_ID,
  ProblemDto.JSON_PROPERTY_ELEMENT_IDS
})
@JsonTypeName("ProblemDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class ProblemDto {
  public static final String JSON_PROPERTY_MESSAGE = "message";
  private String message;

  public static final String JSON_PROPERTY_LINE = "line";
  private Integer line;

  public static final String JSON_PROPERTY_COLUMN = "column";
  private Integer column;

  public static final String JSON_PROPERTY_MAIN_ELEMENT_ID = "mainElementId";
  private String mainElementId;

  public static final String JSON_PROPERTY_ELEMENT_IDS = "elementIds";
  private List<String> elementIds = null;


  public ProblemDto message(String message) {
    
    this.message = message;
    return this;
  }

   /**
   * The message of the problem.
   * @return message
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The message of the problem.")
  @JsonProperty(JSON_PROPERTY_MESSAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMessage() {
    return message;
  }


  public void setMessage(String message) {
    this.message = message;
  }


  public ProblemDto line(Integer line) {
    
    this.line = line;
    return this;
  }

   /**
   * The line where the problem occurred.
   * @return line
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The line where the problem occurred.")
  @JsonProperty(JSON_PROPERTY_LINE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getLine() {
    return line;
  }


  public void setLine(Integer line) {
    this.line = line;
  }


  public ProblemDto column(Integer column) {
    
    this.column = column;
    return this;
  }

   /**
   * The column where the problem occurred.
   * @return column
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The column where the problem occurred.")
  @JsonProperty(JSON_PROPERTY_COLUMN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getColumn() {
    return column;
  }


  public void setColumn(Integer column) {
    this.column = column;
  }


  public ProblemDto mainElementId(String mainElementId) {
    
    this.mainElementId = mainElementId;
    return this;
  }

   /**
   * The main element id where the problem occurred.
   * @return mainElementId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The main element id where the problem occurred.")
  @JsonProperty(JSON_PROPERTY_MAIN_ELEMENT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMainElementId() {
    return mainElementId;
  }


  public void setMainElementId(String mainElementId) {
    this.mainElementId = mainElementId;
  }


  public ProblemDto elementIds(List<String> elementIds) {
    
    this.elementIds = elementIds;
    return this;
  }

  public ProblemDto addElementIdsItem(String elementIdsItem) {
    if (this.elementIds == null) {
      this.elementIds = new ArrayList<>();
    }
    this.elementIds.add(elementIdsItem);
    return this;
  }

   /**
   * A list of element id affected by the problem.
   * @return elementIds
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A list of element id affected by the problem.")
  @JsonProperty(JSON_PROPERTY_ELEMENT_IDS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getElementIds() {
    return elementIds;
  }


  public void setElementIds(List<String> elementIds) {
    this.elementIds = elementIds;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ProblemDto problemDto = (ProblemDto) o;
    return Objects.equals(this.message, problemDto.message) &&
        Objects.equals(this.line, problemDto.line) &&
        Objects.equals(this.column, problemDto.column) &&
        Objects.equals(this.mainElementId, problemDto.mainElementId) &&
        Objects.equals(this.elementIds, problemDto.elementIds);
  }

  @Override
  public int hashCode() {
    return Objects.hash(message, line, column, mainElementId, elementIds);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ProblemDto {\n");
    sb.append("    message: ").append(toIndentedString(message)).append("\n");
    sb.append("    line: ").append(toIndentedString(line)).append("\n");
    sb.append("    column: ").append(toIndentedString(column)).append("\n");
    sb.append("    mainElementId: ").append(toIndentedString(mainElementId)).append("\n");
    sb.append("    elementIds: ").append(toIndentedString(elementIds)).append("\n");
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

