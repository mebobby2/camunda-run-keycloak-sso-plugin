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
 * VariableInstanceDtoAllOf
 */
@JsonPropertyOrder({
  VariableInstanceDtoAllOf.JSON_PROPERTY_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_NAME,
  VariableInstanceDtoAllOf.JSON_PROPERTY_PROCESS_DEFINITION_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_PROCESS_INSTANCE_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_EXECUTION_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_CASE_INSTANCE_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_CASE_EXECUTION_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_TASK_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_BATCH_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_ACTIVITY_INSTANCE_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_TENANT_ID,
  VariableInstanceDtoAllOf.JSON_PROPERTY_ERROR_MESSAGE
})
@JsonTypeName("VariableInstanceDto_allOf")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class VariableInstanceDtoAllOf {
  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_NAME = "name";
  private String name;

  public static final String JSON_PROPERTY_PROCESS_DEFINITION_ID = "processDefinitionId";
  private String processDefinitionId;

  public static final String JSON_PROPERTY_PROCESS_INSTANCE_ID = "processInstanceId";
  private String processInstanceId;

  public static final String JSON_PROPERTY_EXECUTION_ID = "executionId";
  private String executionId;

  public static final String JSON_PROPERTY_CASE_INSTANCE_ID = "caseInstanceId";
  private String caseInstanceId;

  public static final String JSON_PROPERTY_CASE_EXECUTION_ID = "caseExecutionId";
  private String caseExecutionId;

  public static final String JSON_PROPERTY_TASK_ID = "taskId";
  private String taskId;

  public static final String JSON_PROPERTY_BATCH_ID = "batchId";
  private String batchId;

  public static final String JSON_PROPERTY_ACTIVITY_INSTANCE_ID = "activityInstanceId";
  private String activityInstanceId;

  public static final String JSON_PROPERTY_TENANT_ID = "tenantId";
  private String tenantId;

  public static final String JSON_PROPERTY_ERROR_MESSAGE = "errorMessage";
  private String errorMessage;


  public VariableInstanceDtoAllOf id(String id) {
    
    this.id = id;
    return this;
  }

   /**
   * The id of the variable instance.
   * @return id
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the variable instance.")
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getId() {
    return id;
  }


  public void setId(String id) {
    this.id = id;
  }


  public VariableInstanceDtoAllOf name(String name) {
    
    this.name = name;
    return this;
  }

   /**
   * The name of the variable instance.
   * @return name
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The name of the variable instance.")
  @JsonProperty(JSON_PROPERTY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getName() {
    return name;
  }


  public void setName(String name) {
    this.name = name;
  }


  public VariableInstanceDtoAllOf processDefinitionId(String processDefinitionId) {
    
    this.processDefinitionId = processDefinitionId;
    return this;
  }

   /**
   * The id of the process definition that this variable instance belongs to.
   * @return processDefinitionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the process definition that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_PROCESS_DEFINITION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getProcessDefinitionId() {
    return processDefinitionId;
  }


  public void setProcessDefinitionId(String processDefinitionId) {
    this.processDefinitionId = processDefinitionId;
  }


  public VariableInstanceDtoAllOf processInstanceId(String processInstanceId) {
    
    this.processInstanceId = processInstanceId;
    return this;
  }

   /**
   * The id of the process instance that this variable instance belongs to.
   * @return processInstanceId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the process instance that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_PROCESS_INSTANCE_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getProcessInstanceId() {
    return processInstanceId;
  }


  public void setProcessInstanceId(String processInstanceId) {
    this.processInstanceId = processInstanceId;
  }


  public VariableInstanceDtoAllOf executionId(String executionId) {
    
    this.executionId = executionId;
    return this;
  }

   /**
   * The id of the execution that this variable instance belongs to.
   * @return executionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the execution that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_EXECUTION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getExecutionId() {
    return executionId;
  }


  public void setExecutionId(String executionId) {
    this.executionId = executionId;
  }


  public VariableInstanceDtoAllOf caseInstanceId(String caseInstanceId) {
    
    this.caseInstanceId = caseInstanceId;
    return this;
  }

   /**
   * The id of the case instance that this variable instance belongs to.
   * @return caseInstanceId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the case instance that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_CASE_INSTANCE_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getCaseInstanceId() {
    return caseInstanceId;
  }


  public void setCaseInstanceId(String caseInstanceId) {
    this.caseInstanceId = caseInstanceId;
  }


  public VariableInstanceDtoAllOf caseExecutionId(String caseExecutionId) {
    
    this.caseExecutionId = caseExecutionId;
    return this;
  }

   /**
   * The id of the case execution that this variable instance belongs to.
   * @return caseExecutionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the case execution that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_CASE_EXECUTION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getCaseExecutionId() {
    return caseExecutionId;
  }


  public void setCaseExecutionId(String caseExecutionId) {
    this.caseExecutionId = caseExecutionId;
  }


  public VariableInstanceDtoAllOf taskId(String taskId) {
    
    this.taskId = taskId;
    return this;
  }

   /**
   * The id of the task that this variable instance belongs to.
   * @return taskId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the task that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_TASK_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getTaskId() {
    return taskId;
  }


  public void setTaskId(String taskId) {
    this.taskId = taskId;
  }


  public VariableInstanceDtoAllOf batchId(String batchId) {
    
    this.batchId = batchId;
    return this;
  }

   /**
   * The id of the batch that this variable instance belongs to.&lt;
   * @return batchId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the batch that this variable instance belongs to.<")
  @JsonProperty(JSON_PROPERTY_BATCH_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getBatchId() {
    return batchId;
  }


  public void setBatchId(String batchId) {
    this.batchId = batchId;
  }


  public VariableInstanceDtoAllOf activityInstanceId(String activityInstanceId) {
    
    this.activityInstanceId = activityInstanceId;
    return this;
  }

   /**
   * The id of the activity instance that this variable instance belongs to.
   * @return activityInstanceId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the activity instance that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_ACTIVITY_INSTANCE_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getActivityInstanceId() {
    return activityInstanceId;
  }


  public void setActivityInstanceId(String activityInstanceId) {
    this.activityInstanceId = activityInstanceId;
  }


  public VariableInstanceDtoAllOf tenantId(String tenantId) {
    
    this.tenantId = tenantId;
    return this;
  }

   /**
   * The id of the tenant that this variable instance belongs to.
   * @return tenantId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the tenant that this variable instance belongs to.")
  @JsonProperty(JSON_PROPERTY_TENANT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getTenantId() {
    return tenantId;
  }


  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }


  public VariableInstanceDtoAllOf errorMessage(String errorMessage) {
    
    this.errorMessage = errorMessage;
    return this;
  }

   /**
   * An error message in case a Java Serialized Object could not be de-serialized.
   * @return errorMessage
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An error message in case a Java Serialized Object could not be de-serialized.")
  @JsonProperty(JSON_PROPERTY_ERROR_MESSAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getErrorMessage() {
    return errorMessage;
  }


  public void setErrorMessage(String errorMessage) {
    this.errorMessage = errorMessage;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VariableInstanceDtoAllOf variableInstanceDtoAllOf = (VariableInstanceDtoAllOf) o;
    return Objects.equals(this.id, variableInstanceDtoAllOf.id) &&
        Objects.equals(this.name, variableInstanceDtoAllOf.name) &&
        Objects.equals(this.processDefinitionId, variableInstanceDtoAllOf.processDefinitionId) &&
        Objects.equals(this.processInstanceId, variableInstanceDtoAllOf.processInstanceId) &&
        Objects.equals(this.executionId, variableInstanceDtoAllOf.executionId) &&
        Objects.equals(this.caseInstanceId, variableInstanceDtoAllOf.caseInstanceId) &&
        Objects.equals(this.caseExecutionId, variableInstanceDtoAllOf.caseExecutionId) &&
        Objects.equals(this.taskId, variableInstanceDtoAllOf.taskId) &&
        Objects.equals(this.batchId, variableInstanceDtoAllOf.batchId) &&
        Objects.equals(this.activityInstanceId, variableInstanceDtoAllOf.activityInstanceId) &&
        Objects.equals(this.tenantId, variableInstanceDtoAllOf.tenantId) &&
        Objects.equals(this.errorMessage, variableInstanceDtoAllOf.errorMessage);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, name, processDefinitionId, processInstanceId, executionId, caseInstanceId, caseExecutionId, taskId, batchId, activityInstanceId, tenantId, errorMessage);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class VariableInstanceDtoAllOf {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    processDefinitionId: ").append(toIndentedString(processDefinitionId)).append("\n");
    sb.append("    processInstanceId: ").append(toIndentedString(processInstanceId)).append("\n");
    sb.append("    executionId: ").append(toIndentedString(executionId)).append("\n");
    sb.append("    caseInstanceId: ").append(toIndentedString(caseInstanceId)).append("\n");
    sb.append("    caseExecutionId: ").append(toIndentedString(caseExecutionId)).append("\n");
    sb.append("    taskId: ").append(toIndentedString(taskId)).append("\n");
    sb.append("    batchId: ").append(toIndentedString(batchId)).append("\n");
    sb.append("    activityInstanceId: ").append(toIndentedString(activityInstanceId)).append("\n");
    sb.append("    tenantId: ").append(toIndentedString(tenantId)).append("\n");
    sb.append("    errorMessage: ").append(toIndentedString(errorMessage)).append("\n");
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

