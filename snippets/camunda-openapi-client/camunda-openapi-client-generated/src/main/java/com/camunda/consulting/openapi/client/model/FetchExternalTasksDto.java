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
import com.camunda.consulting.openapi.client.model.FetchExternalTaskTopicDto;
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
 * FetchExternalTasksDto
 */
@JsonPropertyOrder({
  FetchExternalTasksDto.JSON_PROPERTY_WORKER_ID,
  FetchExternalTasksDto.JSON_PROPERTY_MAX_TASKS,
  FetchExternalTasksDto.JSON_PROPERTY_USE_PRIORITY,
  FetchExternalTasksDto.JSON_PROPERTY_ASYNC_RESPONSE_TIMEOUT,
  FetchExternalTasksDto.JSON_PROPERTY_TOPICS
})
@JsonTypeName("FetchExternalTasksDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class FetchExternalTasksDto {
  public static final String JSON_PROPERTY_WORKER_ID = "workerId";
  private String workerId;

  public static final String JSON_PROPERTY_MAX_TASKS = "maxTasks";
  private Integer maxTasks;

  public static final String JSON_PROPERTY_USE_PRIORITY = "usePriority";
  private Boolean usePriority;

  public static final String JSON_PROPERTY_ASYNC_RESPONSE_TIMEOUT = "asyncResponseTimeout";
  private Long asyncResponseTimeout;

  public static final String JSON_PROPERTY_TOPICS = "topics";
  private List<FetchExternalTaskTopicDto> topics = null;


  public FetchExternalTasksDto workerId(String workerId) {
    
    this.workerId = workerId;
    return this;
  }

   /**
   * **Mandatory.** The id of the worker on which behalf tasks are fetched. The returned tasks are locked for that worker and can only be completed when providing the same worker id.
   * @return workerId
  **/
  @ApiModelProperty(required = true, value = "**Mandatory.** The id of the worker on which behalf tasks are fetched. The returned tasks are locked for that worker and can only be completed when providing the same worker id.")
  @JsonProperty(JSON_PROPERTY_WORKER_ID)
  @JsonInclude(value = JsonInclude.Include.ALWAYS)

  public String getWorkerId() {
    return workerId;
  }


  public void setWorkerId(String workerId) {
    this.workerId = workerId;
  }


  public FetchExternalTasksDto maxTasks(Integer maxTasks) {
    
    this.maxTasks = maxTasks;
    return this;
  }

   /**
   * **Mandatory.** The maximum number of tasks to return.
   * @return maxTasks
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(required = true, value = "**Mandatory.** The maximum number of tasks to return.")
  @JsonProperty(JSON_PROPERTY_MAX_TASKS)
  @JsonInclude(value = JsonInclude.Include.ALWAYS)

  public Integer getMaxTasks() {
    return maxTasks;
  }


  public void setMaxTasks(Integer maxTasks) {
    this.maxTasks = maxTasks;
  }


  public FetchExternalTasksDto usePriority(Boolean usePriority) {
    
    this.usePriority = usePriority;
    return this;
  }

   /**
   * A &#x60;boolean&#x60; value, which indicates whether the task should be fetched based on its priority or arbitrarily.
   * @return usePriority
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A `boolean` value, which indicates whether the task should be fetched based on its priority or arbitrarily.")
  @JsonProperty(JSON_PROPERTY_USE_PRIORITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getUsePriority() {
    return usePriority;
  }


  public void setUsePriority(Boolean usePriority) {
    this.usePriority = usePriority;
  }


  public FetchExternalTasksDto asyncResponseTimeout(Long asyncResponseTimeout) {
    
    this.asyncResponseTimeout = asyncResponseTimeout;
    return this;
  }

   /**
   * The [Long Polling](https://docs.camunda.org/manual/7.16/user-guide/process-engine/external-tasks/#long-polling-to-fetch-and-lock-external-tasks) timeout in milliseconds.  **Note:** The value cannot be set larger than 1.800.000 milliseconds (corresponds to 30 minutes).
   * @return asyncResponseTimeout
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The [Long Polling](https://docs.camunda.org/manual/7.16/user-guide/process-engine/external-tasks/#long-polling-to-fetch-and-lock-external-tasks) timeout in milliseconds.  **Note:** The value cannot be set larger than 1.800.000 milliseconds (corresponds to 30 minutes).")
  @JsonProperty(JSON_PROPERTY_ASYNC_RESPONSE_TIMEOUT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getAsyncResponseTimeout() {
    return asyncResponseTimeout;
  }


  public void setAsyncResponseTimeout(Long asyncResponseTimeout) {
    this.asyncResponseTimeout = asyncResponseTimeout;
  }


  public FetchExternalTasksDto topics(List<FetchExternalTaskTopicDto> topics) {
    
    this.topics = topics;
    return this;
  }

  public FetchExternalTasksDto addTopicsItem(FetchExternalTaskTopicDto topicsItem) {
    if (this.topics == null) {
      this.topics = new ArrayList<>();
    }
    this.topics.add(topicsItem);
    return this;
  }

   /**
   * A JSON array of topic objects for which external tasks should be fetched. The returned tasks may be arbitrarily distributed among these topics. Each topic object has the following properties:
   * @return topics
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A JSON array of topic objects for which external tasks should be fetched. The returned tasks may be arbitrarily distributed among these topics. Each topic object has the following properties:")
  @JsonProperty(JSON_PROPERTY_TOPICS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<FetchExternalTaskTopicDto> getTopics() {
    return topics;
  }


  public void setTopics(List<FetchExternalTaskTopicDto> topics) {
    this.topics = topics;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    FetchExternalTasksDto fetchExternalTasksDto = (FetchExternalTasksDto) o;
    return Objects.equals(this.workerId, fetchExternalTasksDto.workerId) &&
        Objects.equals(this.maxTasks, fetchExternalTasksDto.maxTasks) &&
        Objects.equals(this.usePriority, fetchExternalTasksDto.usePriority) &&
        Objects.equals(this.asyncResponseTimeout, fetchExternalTasksDto.asyncResponseTimeout) &&
        Objects.equals(this.topics, fetchExternalTasksDto.topics);
  }

  @Override
  public int hashCode() {
    return Objects.hash(workerId, maxTasks, usePriority, asyncResponseTimeout, topics);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class FetchExternalTasksDto {\n");
    sb.append("    workerId: ").append(toIndentedString(workerId)).append("\n");
    sb.append("    maxTasks: ").append(toIndentedString(maxTasks)).append("\n");
    sb.append("    usePriority: ").append(toIndentedString(usePriority)).append("\n");
    sb.append("    asyncResponseTimeout: ").append(toIndentedString(asyncResponseTimeout)).append("\n");
    sb.append("    topics: ").append(toIndentedString(topics)).append("\n");
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

