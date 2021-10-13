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
import com.camunda.consulting.openapi.client.model.JobDefinitionQueryDtoSorting;
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
 * A Job definition query which defines a list of Job definitions
 */
@ApiModel(description = "A Job definition query which defines a list of Job definitions")
@JsonPropertyOrder({
  JobDefinitionQueryDto.JSON_PROPERTY_JOB_DEFINITION_ID,
  JobDefinitionQueryDto.JSON_PROPERTY_ACTIVITY_ID_IN,
  JobDefinitionQueryDto.JSON_PROPERTY_PROCESS_DEFINITION_ID,
  JobDefinitionQueryDto.JSON_PROPERTY_PROCESS_DEFINITION_KEY,
  JobDefinitionQueryDto.JSON_PROPERTY_JOB_TYPE,
  JobDefinitionQueryDto.JSON_PROPERTY_JOB_CONFIGURATION,
  JobDefinitionQueryDto.JSON_PROPERTY_ACTIVE,
  JobDefinitionQueryDto.JSON_PROPERTY_SUSPENDED,
  JobDefinitionQueryDto.JSON_PROPERTY_WITH_OVERRIDING_JOB_PRIORITY,
  JobDefinitionQueryDto.JSON_PROPERTY_TENANT_ID_IN,
  JobDefinitionQueryDto.JSON_PROPERTY_WITHOUT_TENANT_ID,
  JobDefinitionQueryDto.JSON_PROPERTY_INCLUDE_JOB_DEFINITIONS_WITHOUT_TENANT_ID,
  JobDefinitionQueryDto.JSON_PROPERTY_SORTING
})
@JsonTypeName("JobDefinitionQueryDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class JobDefinitionQueryDto {
  public static final String JSON_PROPERTY_JOB_DEFINITION_ID = "jobDefinitionId";
  private String jobDefinitionId;

  public static final String JSON_PROPERTY_ACTIVITY_ID_IN = "activityIdIn";
  private List<String> activityIdIn = null;

  public static final String JSON_PROPERTY_PROCESS_DEFINITION_ID = "processDefinitionId";
  private String processDefinitionId;

  public static final String JSON_PROPERTY_PROCESS_DEFINITION_KEY = "processDefinitionKey";
  private String processDefinitionKey;

  public static final String JSON_PROPERTY_JOB_TYPE = "jobType";
  private String jobType;

  public static final String JSON_PROPERTY_JOB_CONFIGURATION = "jobConfiguration";
  private String jobConfiguration;

  public static final String JSON_PROPERTY_ACTIVE = "active";
  private Boolean active;

  public static final String JSON_PROPERTY_SUSPENDED = "suspended";
  private Boolean suspended;

  public static final String JSON_PROPERTY_WITH_OVERRIDING_JOB_PRIORITY = "withOverridingJobPriority";
  private Boolean withOverridingJobPriority;

  public static final String JSON_PROPERTY_TENANT_ID_IN = "tenantIdIn";
  private List<String> tenantIdIn = null;

  public static final String JSON_PROPERTY_WITHOUT_TENANT_ID = "withoutTenantId";
  private Boolean withoutTenantId;

  public static final String JSON_PROPERTY_INCLUDE_JOB_DEFINITIONS_WITHOUT_TENANT_ID = "includeJobDefinitionsWithoutTenantId";
  private Boolean includeJobDefinitionsWithoutTenantId;

  public static final String JSON_PROPERTY_SORTING = "sorting";
  private List<JobDefinitionQueryDtoSorting> sorting = null;


  public JobDefinitionQueryDto jobDefinitionId(String jobDefinitionId) {
    
    this.jobDefinitionId = jobDefinitionId;
    return this;
  }

   /**
   * Filter by job definition id.
   * @return jobDefinitionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Filter by job definition id.")
  @JsonProperty(JSON_PROPERTY_JOB_DEFINITION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getJobDefinitionId() {
    return jobDefinitionId;
  }


  public void setJobDefinitionId(String jobDefinitionId) {
    this.jobDefinitionId = jobDefinitionId;
  }


  public JobDefinitionQueryDto activityIdIn(List<String> activityIdIn) {
    
    this.activityIdIn = activityIdIn;
    return this;
  }

  public JobDefinitionQueryDto addActivityIdInItem(String activityIdInItem) {
    if (this.activityIdIn == null) {
      this.activityIdIn = new ArrayList<>();
    }
    this.activityIdIn.add(activityIdInItem);
    return this;
  }

   /**
   * Only include job definitions which belong to one of the passed activity ids.
   * @return activityIdIn
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions which belong to one of the passed activity ids.")
  @JsonProperty(JSON_PROPERTY_ACTIVITY_ID_IN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getActivityIdIn() {
    return activityIdIn;
  }


  public void setActivityIdIn(List<String> activityIdIn) {
    this.activityIdIn = activityIdIn;
  }


  public JobDefinitionQueryDto processDefinitionId(String processDefinitionId) {
    
    this.processDefinitionId = processDefinitionId;
    return this;
  }

   /**
   * Only include job definitions which exist for the given process definition id.
   * @return processDefinitionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions which exist for the given process definition id.")
  @JsonProperty(JSON_PROPERTY_PROCESS_DEFINITION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getProcessDefinitionId() {
    return processDefinitionId;
  }


  public void setProcessDefinitionId(String processDefinitionId) {
    this.processDefinitionId = processDefinitionId;
  }


  public JobDefinitionQueryDto processDefinitionKey(String processDefinitionKey) {
    
    this.processDefinitionKey = processDefinitionKey;
    return this;
  }

   /**
   * Only include job definitions which exist for the given process definition key.
   * @return processDefinitionKey
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions which exist for the given process definition key.")
  @JsonProperty(JSON_PROPERTY_PROCESS_DEFINITION_KEY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getProcessDefinitionKey() {
    return processDefinitionKey;
  }


  public void setProcessDefinitionKey(String processDefinitionKey) {
    this.processDefinitionKey = processDefinitionKey;
  }


  public JobDefinitionQueryDto jobType(String jobType) {
    
    this.jobType = jobType;
    return this;
  }

   /**
   * Only include job definitions which exist for the given job type. See the [User Guide](https://docs.camunda.org/manual/7.16/user-guide/process-engine/the-job-executor/#job-creation) for more information about job types.
   * @return jobType
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions which exist for the given job type. See the [User Guide](https://docs.camunda.org/manual/7.16/user-guide/process-engine/the-job-executor/#job-creation) for more information about job types.")
  @JsonProperty(JSON_PROPERTY_JOB_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getJobType() {
    return jobType;
  }


  public void setJobType(String jobType) {
    this.jobType = jobType;
  }


  public JobDefinitionQueryDto jobConfiguration(String jobConfiguration) {
    
    this.jobConfiguration = jobConfiguration;
    return this;
  }

   /**
   * Only include job definitions which exist for the given job configuration. For example: for timer jobs it is the timer configuration.
   * @return jobConfiguration
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions which exist for the given job configuration. For example: for timer jobs it is the timer configuration.")
  @JsonProperty(JSON_PROPERTY_JOB_CONFIGURATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getJobConfiguration() {
    return jobConfiguration;
  }


  public void setJobConfiguration(String jobConfiguration) {
    this.jobConfiguration = jobConfiguration;
  }


  public JobDefinitionQueryDto active(Boolean active) {
    
    this.active = active;
    return this;
  }

   /**
   * Only include active job definitions. Value may only be &#x60;true&#x60;, as &#x60;false&#x60; is the default behavior.
   * @return active
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include active job definitions. Value may only be `true`, as `false` is the default behavior.")
  @JsonProperty(JSON_PROPERTY_ACTIVE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getActive() {
    return active;
  }


  public void setActive(Boolean active) {
    this.active = active;
  }


  public JobDefinitionQueryDto suspended(Boolean suspended) {
    
    this.suspended = suspended;
    return this;
  }

   /**
   * Only include suspended job definitions. Value may only be &#x60;true&#x60;, as &#x60;false&#x60; is the default behavior.
   * @return suspended
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include suspended job definitions. Value may only be `true`, as `false` is the default behavior.")
  @JsonProperty(JSON_PROPERTY_SUSPENDED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getSuspended() {
    return suspended;
  }


  public void setSuspended(Boolean suspended) {
    this.suspended = suspended;
  }


  public JobDefinitionQueryDto withOverridingJobPriority(Boolean withOverridingJobPriority) {
    
    this.withOverridingJobPriority = withOverridingJobPriority;
    return this;
  }

   /**
   * Only include job definitions that have an overriding job priority defined. The only effective value is &#x60;true&#x60;. If set to &#x60;false&#x60;, this filter is not applied.
   * @return withOverridingJobPriority
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions that have an overriding job priority defined. The only effective value is `true`. If set to `false`, this filter is not applied.")
  @JsonProperty(JSON_PROPERTY_WITH_OVERRIDING_JOB_PRIORITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getWithOverridingJobPriority() {
    return withOverridingJobPriority;
  }


  public void setWithOverridingJobPriority(Boolean withOverridingJobPriority) {
    this.withOverridingJobPriority = withOverridingJobPriority;
  }


  public JobDefinitionQueryDto tenantIdIn(List<String> tenantIdIn) {
    
    this.tenantIdIn = tenantIdIn;
    return this;
  }

  public JobDefinitionQueryDto addTenantIdInItem(String tenantIdInItem) {
    if (this.tenantIdIn == null) {
      this.tenantIdIn = new ArrayList<>();
    }
    this.tenantIdIn.add(tenantIdInItem);
    return this;
  }

   /**
   * Only include job definitions which belong to one of the passed tenant ids.
   * @return tenantIdIn
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions which belong to one of the passed tenant ids.")
  @JsonProperty(JSON_PROPERTY_TENANT_ID_IN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getTenantIdIn() {
    return tenantIdIn;
  }


  public void setTenantIdIn(List<String> tenantIdIn) {
    this.tenantIdIn = tenantIdIn;
  }


  public JobDefinitionQueryDto withoutTenantId(Boolean withoutTenantId) {
    
    this.withoutTenantId = withoutTenantId;
    return this;
  }

   /**
   * Only include job definitions which belong to no tenant. Value may only be &#x60;true&#x60;, as &#x60;false&#x60; is the default behavior.
   * @return withoutTenantId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only include job definitions which belong to no tenant. Value may only be `true`, as `false` is the default behavior.")
  @JsonProperty(JSON_PROPERTY_WITHOUT_TENANT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getWithoutTenantId() {
    return withoutTenantId;
  }


  public void setWithoutTenantId(Boolean withoutTenantId) {
    this.withoutTenantId = withoutTenantId;
  }


  public JobDefinitionQueryDto includeJobDefinitionsWithoutTenantId(Boolean includeJobDefinitionsWithoutTenantId) {
    
    this.includeJobDefinitionsWithoutTenantId = includeJobDefinitionsWithoutTenantId;
    return this;
  }

   /**
   * Include job definitions which belong to no tenant. Can be used in combination with &#x60;tenantIdIn&#x60;. Value may only be &#x60;true&#x60;, as &#x60;false&#x60; is the default behavior.
   * @return includeJobDefinitionsWithoutTenantId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Include job definitions which belong to no tenant. Can be used in combination with `tenantIdIn`. Value may only be `true`, as `false` is the default behavior.")
  @JsonProperty(JSON_PROPERTY_INCLUDE_JOB_DEFINITIONS_WITHOUT_TENANT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getIncludeJobDefinitionsWithoutTenantId() {
    return includeJobDefinitionsWithoutTenantId;
  }


  public void setIncludeJobDefinitionsWithoutTenantId(Boolean includeJobDefinitionsWithoutTenantId) {
    this.includeJobDefinitionsWithoutTenantId = includeJobDefinitionsWithoutTenantId;
  }


  public JobDefinitionQueryDto sorting(List<JobDefinitionQueryDtoSorting> sorting) {
    
    this.sorting = sorting;
    return this;
  }

  public JobDefinitionQueryDto addSortingItem(JobDefinitionQueryDtoSorting sortingItem) {
    if (this.sorting == null) {
      this.sorting = new ArrayList<>();
    }
    this.sorting.add(sortingItem);
    return this;
  }

   /**
   * An array of criteria to sort the result by. Each element of the array is                        an object that specifies one ordering. The position in the array                        identifies the rank of an ordering, i.e., whether it is primary, secondary,                        etc. Sorting has no effect for &#x60;count&#x60; endpoints.
   * @return sorting
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An array of criteria to sort the result by. Each element of the array is                        an object that specifies one ordering. The position in the array                        identifies the rank of an ordering, i.e., whether it is primary, secondary,                        etc. Sorting has no effect for `count` endpoints.")
  @JsonProperty(JSON_PROPERTY_SORTING)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<JobDefinitionQueryDtoSorting> getSorting() {
    return sorting;
  }


  public void setSorting(List<JobDefinitionQueryDtoSorting> sorting) {
    this.sorting = sorting;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    JobDefinitionQueryDto jobDefinitionQueryDto = (JobDefinitionQueryDto) o;
    return Objects.equals(this.jobDefinitionId, jobDefinitionQueryDto.jobDefinitionId) &&
        Objects.equals(this.activityIdIn, jobDefinitionQueryDto.activityIdIn) &&
        Objects.equals(this.processDefinitionId, jobDefinitionQueryDto.processDefinitionId) &&
        Objects.equals(this.processDefinitionKey, jobDefinitionQueryDto.processDefinitionKey) &&
        Objects.equals(this.jobType, jobDefinitionQueryDto.jobType) &&
        Objects.equals(this.jobConfiguration, jobDefinitionQueryDto.jobConfiguration) &&
        Objects.equals(this.active, jobDefinitionQueryDto.active) &&
        Objects.equals(this.suspended, jobDefinitionQueryDto.suspended) &&
        Objects.equals(this.withOverridingJobPriority, jobDefinitionQueryDto.withOverridingJobPriority) &&
        Objects.equals(this.tenantIdIn, jobDefinitionQueryDto.tenantIdIn) &&
        Objects.equals(this.withoutTenantId, jobDefinitionQueryDto.withoutTenantId) &&
        Objects.equals(this.includeJobDefinitionsWithoutTenantId, jobDefinitionQueryDto.includeJobDefinitionsWithoutTenantId) &&
        Objects.equals(this.sorting, jobDefinitionQueryDto.sorting);
  }

  @Override
  public int hashCode() {
    return Objects.hash(jobDefinitionId, activityIdIn, processDefinitionId, processDefinitionKey, jobType, jobConfiguration, active, suspended, withOverridingJobPriority, tenantIdIn, withoutTenantId, includeJobDefinitionsWithoutTenantId, sorting);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class JobDefinitionQueryDto {\n");
    sb.append("    jobDefinitionId: ").append(toIndentedString(jobDefinitionId)).append("\n");
    sb.append("    activityIdIn: ").append(toIndentedString(activityIdIn)).append("\n");
    sb.append("    processDefinitionId: ").append(toIndentedString(processDefinitionId)).append("\n");
    sb.append("    processDefinitionKey: ").append(toIndentedString(processDefinitionKey)).append("\n");
    sb.append("    jobType: ").append(toIndentedString(jobType)).append("\n");
    sb.append("    jobConfiguration: ").append(toIndentedString(jobConfiguration)).append("\n");
    sb.append("    active: ").append(toIndentedString(active)).append("\n");
    sb.append("    suspended: ").append(toIndentedString(suspended)).append("\n");
    sb.append("    withOverridingJobPriority: ").append(toIndentedString(withOverridingJobPriority)).append("\n");
    sb.append("    tenantIdIn: ").append(toIndentedString(tenantIdIn)).append("\n");
    sb.append("    withoutTenantId: ").append(toIndentedString(withoutTenantId)).append("\n");
    sb.append("    includeJobDefinitionsWithoutTenantId: ").append(toIndentedString(includeJobDefinitionsWithoutTenantId)).append("\n");
    sb.append("    sorting: ").append(toIndentedString(sorting)).append("\n");
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

