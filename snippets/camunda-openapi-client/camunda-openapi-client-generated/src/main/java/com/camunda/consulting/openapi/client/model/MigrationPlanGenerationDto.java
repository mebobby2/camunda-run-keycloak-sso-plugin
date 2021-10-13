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
import com.camunda.consulting.openapi.client.model.VariableValueDto;
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
 * MigrationPlanGenerationDto
 */
@JsonPropertyOrder({
  MigrationPlanGenerationDto.JSON_PROPERTY_SOURCE_PROCESS_DEFINITION_ID,
  MigrationPlanGenerationDto.JSON_PROPERTY_TARGET_PROCESS_DEFINITION_ID,
  MigrationPlanGenerationDto.JSON_PROPERTY_UPDATE_EVENT_TRIGGERS,
  MigrationPlanGenerationDto.JSON_PROPERTY_VARIABLES
})
@JsonTypeName("MigrationPlanGenerationDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class MigrationPlanGenerationDto {
  public static final String JSON_PROPERTY_SOURCE_PROCESS_DEFINITION_ID = "sourceProcessDefinitionId";
  private String sourceProcessDefinitionId;

  public static final String JSON_PROPERTY_TARGET_PROCESS_DEFINITION_ID = "targetProcessDefinitionId";
  private String targetProcessDefinitionId;

  public static final String JSON_PROPERTY_UPDATE_EVENT_TRIGGERS = "updateEventTriggers";
  private Boolean updateEventTriggers;

  public static final String JSON_PROPERTY_VARIABLES = "variables";
  private Map<String, VariableValueDto> variables = null;


  public MigrationPlanGenerationDto sourceProcessDefinitionId(String sourceProcessDefinitionId) {
    
    this.sourceProcessDefinitionId = sourceProcessDefinitionId;
    return this;
  }

   /**
   * The id of the source process definition for the migration.
   * @return sourceProcessDefinitionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the source process definition for the migration.")
  @JsonProperty(JSON_PROPERTY_SOURCE_PROCESS_DEFINITION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getSourceProcessDefinitionId() {
    return sourceProcessDefinitionId;
  }


  public void setSourceProcessDefinitionId(String sourceProcessDefinitionId) {
    this.sourceProcessDefinitionId = sourceProcessDefinitionId;
  }


  public MigrationPlanGenerationDto targetProcessDefinitionId(String targetProcessDefinitionId) {
    
    this.targetProcessDefinitionId = targetProcessDefinitionId;
    return this;
  }

   /**
   * The id of the target process definition for the migration.
   * @return targetProcessDefinitionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the target process definition for the migration.")
  @JsonProperty(JSON_PROPERTY_TARGET_PROCESS_DEFINITION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getTargetProcessDefinitionId() {
    return targetProcessDefinitionId;
  }


  public void setTargetProcessDefinitionId(String targetProcessDefinitionId) {
    this.targetProcessDefinitionId = targetProcessDefinitionId;
  }


  public MigrationPlanGenerationDto updateEventTriggers(Boolean updateEventTriggers) {
    
    this.updateEventTriggers = updateEventTriggers;
    return this;
  }

   /**
   * A boolean flag indicating whether instructions between events should be configured to update the event triggers.
   * @return updateEventTriggers
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A boolean flag indicating whether instructions between events should be configured to update the event triggers.")
  @JsonProperty(JSON_PROPERTY_UPDATE_EVENT_TRIGGERS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getUpdateEventTriggers() {
    return updateEventTriggers;
  }


  public void setUpdateEventTriggers(Boolean updateEventTriggers) {
    this.updateEventTriggers = updateEventTriggers;
  }


  public MigrationPlanGenerationDto variables(Map<String, VariableValueDto> variables) {
    
    this.variables = variables;
    return this;
  }

  public MigrationPlanGenerationDto putVariablesItem(String key, VariableValueDto variablesItem) {
    if (this.variables == null) {
      this.variables = new HashMap<>();
    }
    this.variables.put(key, variablesItem);
    return this;
  }

   /**
   * A map of variables which will be set into the process instances&#39; scope. Each key is a variable name and each value a JSON variable value object.
   * @return variables
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A map of variables which will be set into the process instances' scope. Each key is a variable name and each value a JSON variable value object.")
  @JsonProperty(JSON_PROPERTY_VARIABLES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, VariableValueDto> getVariables() {
    return variables;
  }


  public void setVariables(Map<String, VariableValueDto> variables) {
    this.variables = variables;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MigrationPlanGenerationDto migrationPlanGenerationDto = (MigrationPlanGenerationDto) o;
    return Objects.equals(this.sourceProcessDefinitionId, migrationPlanGenerationDto.sourceProcessDefinitionId) &&
        Objects.equals(this.targetProcessDefinitionId, migrationPlanGenerationDto.targetProcessDefinitionId) &&
        Objects.equals(this.updateEventTriggers, migrationPlanGenerationDto.updateEventTriggers) &&
        Objects.equals(this.variables, migrationPlanGenerationDto.variables);
  }

  @Override
  public int hashCode() {
    return Objects.hash(sourceProcessDefinitionId, targetProcessDefinitionId, updateEventTriggers, variables);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MigrationPlanGenerationDto {\n");
    sb.append("    sourceProcessDefinitionId: ").append(toIndentedString(sourceProcessDefinitionId)).append("\n");
    sb.append("    targetProcessDefinitionId: ").append(toIndentedString(targetProcessDefinitionId)).append("\n");
    sb.append("    updateEventTriggers: ").append(toIndentedString(updateEventTriggers)).append("\n");
    sb.append("    variables: ").append(toIndentedString(variables)).append("\n");
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

