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
 * CreateIncidentDto
 */
@JsonPropertyOrder({
  CreateIncidentDto.JSON_PROPERTY_INCIDENT_TYPE,
  CreateIncidentDto.JSON_PROPERTY_CONFIGURATION,
  CreateIncidentDto.JSON_PROPERTY_MESSAGE
})
@JsonTypeName("CreateIncidentDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class CreateIncidentDto {
  public static final String JSON_PROPERTY_INCIDENT_TYPE = "incidentType";
  private String incidentType;

  public static final String JSON_PROPERTY_CONFIGURATION = "configuration";
  private String _configuration;

  public static final String JSON_PROPERTY_MESSAGE = "message";
  private String message;


  public CreateIncidentDto incidentType(String incidentType) {
    
    this.incidentType = incidentType;
    return this;
  }

   /**
   * A type of the new incident.
   * @return incidentType
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A type of the new incident.")
  @JsonProperty(JSON_PROPERTY_INCIDENT_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getIncidentType() {
    return incidentType;
  }


  public void setIncidentType(String incidentType) {
    this.incidentType = incidentType;
  }


  public CreateIncidentDto _configuration(String _configuration) {
    
    this._configuration = _configuration;
    return this;
  }

   /**
   * A configuration for the new incident.
   * @return _configuration
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A configuration for the new incident.")
  @JsonProperty(JSON_PROPERTY_CONFIGURATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getConfiguration() {
    return _configuration;
  }


  public void setConfiguration(String _configuration) {
    this._configuration = _configuration;
  }


  public CreateIncidentDto message(String message) {
    
    this.message = message;
    return this;
  }

   /**
   * A message for the new incident.
   * @return message
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A message for the new incident.")
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
    CreateIncidentDto createIncidentDto = (CreateIncidentDto) o;
    return Objects.equals(this.incidentType, createIncidentDto.incidentType) &&
        Objects.equals(this._configuration, createIncidentDto._configuration) &&
        Objects.equals(this.message, createIncidentDto.message);
  }

  @Override
  public int hashCode() {
    return Objects.hash(incidentType, _configuration, message);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CreateIncidentDto {\n");
    sb.append("    incidentType: ").append(toIndentedString(incidentType)).append("\n");
    sb.append("    _configuration: ").append(toIndentedString(_configuration)).append("\n");
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

