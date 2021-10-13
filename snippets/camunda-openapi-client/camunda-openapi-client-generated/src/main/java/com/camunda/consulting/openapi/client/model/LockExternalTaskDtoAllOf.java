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
 * LockExternalTaskDtoAllOf
 */
@JsonPropertyOrder({
  LockExternalTaskDtoAllOf.JSON_PROPERTY_LOCK_DURATION
})
@JsonTypeName("LockExternalTaskDto_allOf")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class LockExternalTaskDtoAllOf {
  public static final String JSON_PROPERTY_LOCK_DURATION = "lockDuration";
  private Long lockDuration;


  public LockExternalTaskDtoAllOf lockDuration(Long lockDuration) {
    
    this.lockDuration = lockDuration;
    return this;
  }

   /**
   * The duration to lock the external task for in milliseconds. **Note:** Attempting to lock an already locked external task with the same &#x60;workerId&#x60; will succeed and a new lock duration will be set, starting from the current moment.
   * @return lockDuration
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The duration to lock the external task for in milliseconds. **Note:** Attempting to lock an already locked external task with the same `workerId` will succeed and a new lock duration will be set, starting from the current moment.")
  @JsonProperty(JSON_PROPERTY_LOCK_DURATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getLockDuration() {
    return lockDuration;
  }


  public void setLockDuration(Long lockDuration) {
    this.lockDuration = lockDuration;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    LockExternalTaskDtoAllOf lockExternalTaskDtoAllOf = (LockExternalTaskDtoAllOf) o;
    return Objects.equals(this.lockDuration, lockExternalTaskDtoAllOf.lockDuration);
  }

  @Override
  public int hashCode() {
    return Objects.hash(lockDuration);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class LockExternalTaskDtoAllOf {\n");
    sb.append("    lockDuration: ").append(toIndentedString(lockDuration)).append("\n");
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

