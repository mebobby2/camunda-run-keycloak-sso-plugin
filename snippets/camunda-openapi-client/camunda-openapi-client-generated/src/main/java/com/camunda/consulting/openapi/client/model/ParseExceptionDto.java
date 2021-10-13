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
import com.camunda.consulting.openapi.client.model.ExceptionDto;
import com.camunda.consulting.openapi.client.model.ParseExceptionDtoAllOf;
import com.camunda.consulting.openapi.client.model.ResourceReportDto;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * ParseExceptionDto
 */
@JsonPropertyOrder({
  ParseExceptionDto.JSON_PROPERTY_DETAILS,
  ParseExceptionDto.JSON_PROPERTY_TYPE,
  ParseExceptionDto.JSON_PROPERTY_MESSAGE
})
@JsonTypeName("ParseExceptionDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class ParseExceptionDto {
  public static final String JSON_PROPERTY_DETAILS = "details";
  private Map<String, ResourceReportDto> details = null;

  public static final String JSON_PROPERTY_TYPE = "type";
  private String type;

  public static final String JSON_PROPERTY_MESSAGE = "message";
  private String message;


  public ParseExceptionDto details(Map<String, ResourceReportDto> details) {
    
    this.details = details;
    return this;
  }

  public ParseExceptionDto putDetailsItem(String key, ResourceReportDto detailsItem) {
    if (this.details == null) {
      this.details = new HashMap<>();
    }
    this.details.put(key, detailsItem);
    return this;
  }

   /**
   * A JSON Object containing list of errors and warnings occurred during deployment.
   * @return details
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A JSON Object containing list of errors and warnings occurred during deployment.")
  @JsonProperty(JSON_PROPERTY_DETAILS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, ResourceReportDto> getDetails() {
    return details;
  }


  public void setDetails(Map<String, ResourceReportDto> details) {
    this.details = details;
  }


  public ParseExceptionDto type(String type) {
    
    this.type = type;
    return this;
  }

   /**
   * An exception class indicating the occurred error.
   * @return type
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An exception class indicating the occurred error.")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getType() {
    return type;
  }


  public void setType(String type) {
    this.type = type;
  }


  public ParseExceptionDto message(String message) {
    
    this.message = message;
    return this;
  }

   /**
   * A detailed message of the error.
   * @return message
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A detailed message of the error.")
  @JsonProperty(JSON_PROPERTY_MESSAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMessage() {
    return message;
  }


  public void setMessage(String message) {
    this.message = message;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ParseExceptionDto parseExceptionDto = (ParseExceptionDto) o;
    return Objects.equals(this.details, parseExceptionDto.details) &&
        Objects.equals(this.type, parseExceptionDto.type) &&
        Objects.equals(this.message, parseExceptionDto.message);
  }

  @Override
  public int hashCode() {
    return Objects.hash(details, type, message);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ParseExceptionDto {\n");
    sb.append("    details: ").append(toIndentedString(details)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
    sb.append("    message: ").append(toIndentedString(message)).append("\n");
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

