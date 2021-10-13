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
import com.camunda.consulting.openapi.client.model.MigrationPlanDto;
import com.camunda.consulting.openapi.client.model.ProcessInstanceQueryDto;
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
 * MigrationExecutionDto
 */
@JsonPropertyOrder({
  MigrationExecutionDto.JSON_PROPERTY_MIGRATION_PLAN,
  MigrationExecutionDto.JSON_PROPERTY_PROCESS_INSTANCE_IDS,
  MigrationExecutionDto.JSON_PROPERTY_PROCESS_INSTANCE_QUERY,
  MigrationExecutionDto.JSON_PROPERTY_SKIP_CUSTOM_LISTENERS,
  MigrationExecutionDto.JSON_PROPERTY_SKIP_IO_MAPPINGS
})
@JsonTypeName("MigrationExecutionDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class MigrationExecutionDto {
  public static final String JSON_PROPERTY_MIGRATION_PLAN = "migrationPlan";
  private MigrationPlanDto migrationPlan;

  public static final String JSON_PROPERTY_PROCESS_INSTANCE_IDS = "processInstanceIds";
  private List<String> processInstanceIds = null;

  public static final String JSON_PROPERTY_PROCESS_INSTANCE_QUERY = "processInstanceQuery";
  private ProcessInstanceQueryDto processInstanceQuery;

  public static final String JSON_PROPERTY_SKIP_CUSTOM_LISTENERS = "skipCustomListeners";
  private Boolean skipCustomListeners;

  public static final String JSON_PROPERTY_SKIP_IO_MAPPINGS = "skipIoMappings";
  private Boolean skipIoMappings;


  public MigrationExecutionDto migrationPlan(MigrationPlanDto migrationPlan) {
    
    this.migrationPlan = migrationPlan;
    return this;
  }

   /**
   * Get migrationPlan
   * @return migrationPlan
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_MIGRATION_PLAN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public MigrationPlanDto getMigrationPlan() {
    return migrationPlan;
  }


  public void setMigrationPlan(MigrationPlanDto migrationPlan) {
    this.migrationPlan = migrationPlan;
  }


  public MigrationExecutionDto processInstanceIds(List<String> processInstanceIds) {
    
    this.processInstanceIds = processInstanceIds;
    return this;
  }

  public MigrationExecutionDto addProcessInstanceIdsItem(String processInstanceIdsItem) {
    if (this.processInstanceIds == null) {
      this.processInstanceIds = new ArrayList<>();
    }
    this.processInstanceIds.add(processInstanceIdsItem);
    return this;
  }

   /**
   * A list of process instance ids to migrate.
   * @return processInstanceIds
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A list of process instance ids to migrate.")
  @JsonProperty(JSON_PROPERTY_PROCESS_INSTANCE_IDS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getProcessInstanceIds() {
    return processInstanceIds;
  }


  public void setProcessInstanceIds(List<String> processInstanceIds) {
    this.processInstanceIds = processInstanceIds;
  }


  public MigrationExecutionDto processInstanceQuery(ProcessInstanceQueryDto processInstanceQuery) {
    
    this.processInstanceQuery = processInstanceQuery;
    return this;
  }

   /**
   * Get processInstanceQuery
   * @return processInstanceQuery
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_PROCESS_INSTANCE_QUERY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public ProcessInstanceQueryDto getProcessInstanceQuery() {
    return processInstanceQuery;
  }


  public void setProcessInstanceQuery(ProcessInstanceQueryDto processInstanceQuery) {
    this.processInstanceQuery = processInstanceQuery;
  }


  public MigrationExecutionDto skipCustomListeners(Boolean skipCustomListeners) {
    
    this.skipCustomListeners = skipCustomListeners;
    return this;
  }

   /**
   * A boolean value to control whether execution listeners should be invoked during migration.
   * @return skipCustomListeners
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A boolean value to control whether execution listeners should be invoked during migration.")
  @JsonProperty(JSON_PROPERTY_SKIP_CUSTOM_LISTENERS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getSkipCustomListeners() {
    return skipCustomListeners;
  }


  public void setSkipCustomListeners(Boolean skipCustomListeners) {
    this.skipCustomListeners = skipCustomListeners;
  }


  public MigrationExecutionDto skipIoMappings(Boolean skipIoMappings) {
    
    this.skipIoMappings = skipIoMappings;
    return this;
  }

   /**
   * A boolean value to control whether input/output mappings should be executed during migration.
   * @return skipIoMappings
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A boolean value to control whether input/output mappings should be executed during migration.")
  @JsonProperty(JSON_PROPERTY_SKIP_IO_MAPPINGS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getSkipIoMappings() {
    return skipIoMappings;
  }


  public void setSkipIoMappings(Boolean skipIoMappings) {
    this.skipIoMappings = skipIoMappings;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MigrationExecutionDto migrationExecutionDto = (MigrationExecutionDto) o;
    return Objects.equals(this.migrationPlan, migrationExecutionDto.migrationPlan) &&
        Objects.equals(this.processInstanceIds, migrationExecutionDto.processInstanceIds) &&
        Objects.equals(this.processInstanceQuery, migrationExecutionDto.processInstanceQuery) &&
        Objects.equals(this.skipCustomListeners, migrationExecutionDto.skipCustomListeners) &&
        Objects.equals(this.skipIoMappings, migrationExecutionDto.skipIoMappings);
  }

  @Override
  public int hashCode() {
    return Objects.hash(migrationPlan, processInstanceIds, processInstanceQuery, skipCustomListeners, skipIoMappings);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MigrationExecutionDto {\n");
    sb.append("    migrationPlan: ").append(toIndentedString(migrationPlan)).append("\n");
    sb.append("    processInstanceIds: ").append(toIndentedString(processInstanceIds)).append("\n");
    sb.append("    processInstanceQuery: ").append(toIndentedString(processInstanceQuery)).append("\n");
    sb.append("    skipCustomListeners: ").append(toIndentedString(skipCustomListeners)).append("\n");
    sb.append("    skipIoMappings: ").append(toIndentedString(skipIoMappings)).append("\n");
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

