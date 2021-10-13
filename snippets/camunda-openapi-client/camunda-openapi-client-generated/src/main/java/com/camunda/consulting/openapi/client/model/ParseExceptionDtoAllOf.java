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
 * ParseExceptionDtoAllOf
 */
@JsonPropertyOrder({
  ParseExceptionDtoAllOf.JSON_PROPERTY_DETAILS
})
@JsonTypeName("ParseExceptionDto_allOf")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class ParseExceptionDtoAllOf {
  public static final String JSON_PROPERTY_DETAILS = "details";
  private Map<String, ResourceReportDto> details = null;


  public ParseExceptionDtoAllOf details(Map<String, ResourceReportDto> details) {
    
    this.details = details;
    return this;
  }

  public ParseExceptionDtoAllOf putDetailsItem(String key, ResourceReportDto detailsItem) {
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


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ParseExceptionDtoAllOf parseExceptionDtoAllOf = (ParseExceptionDtoAllOf) o;
    return Objects.equals(this.details, parseExceptionDtoAllOf.details);
  }

  @Override
  public int hashCode() {
    return Objects.hash(details);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ParseExceptionDtoAllOf {\n");
    sb.append("    details: ").append(toIndentedString(details)).append("\n");
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

