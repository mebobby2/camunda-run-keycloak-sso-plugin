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
 * CleanableHistoricDecisionInstanceReportResultDto
 */
@JsonPropertyOrder({
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_DECISION_DEFINITION_ID,
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_DECISION_DEFINITION_KEY,
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_DECISION_DEFINITION_NAME,
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_DECISION_DEFINITION_VERSION,
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_HISTORY_TIME_TO_LIVE,
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_FINISHED_DECISION_INSTANCE_COUNT,
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_CLEANABLE_DECISION_INSTANCE_COUNT,
  CleanableHistoricDecisionInstanceReportResultDto.JSON_PROPERTY_TENANT_ID
})
@JsonTypeName("CleanableHistoricDecisionInstanceReportResultDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class CleanableHistoricDecisionInstanceReportResultDto {
  public static final String JSON_PROPERTY_DECISION_DEFINITION_ID = "decisionDefinitionId";
  private String decisionDefinitionId;

  public static final String JSON_PROPERTY_DECISION_DEFINITION_KEY = "decisionDefinitionKey";
  private String decisionDefinitionKey;

  public static final String JSON_PROPERTY_DECISION_DEFINITION_NAME = "decisionDefinitionName";
  private String decisionDefinitionName;

  public static final String JSON_PROPERTY_DECISION_DEFINITION_VERSION = "decisionDefinitionVersion";
  private Integer decisionDefinitionVersion;

  public static final String JSON_PROPERTY_HISTORY_TIME_TO_LIVE = "historyTimeToLive";
  private Integer historyTimeToLive;

  public static final String JSON_PROPERTY_FINISHED_DECISION_INSTANCE_COUNT = "finishedDecisionInstanceCount";
  private Long finishedDecisionInstanceCount;

  public static final String JSON_PROPERTY_CLEANABLE_DECISION_INSTANCE_COUNT = "cleanableDecisionInstanceCount";
  private Long cleanableDecisionInstanceCount;

  public static final String JSON_PROPERTY_TENANT_ID = "tenantId";
  private String tenantId;


  public CleanableHistoricDecisionInstanceReportResultDto decisionDefinitionId(String decisionDefinitionId) {
    
    this.decisionDefinitionId = decisionDefinitionId;
    return this;
  }

   /**
   * The id of the decision definition.
   * @return decisionDefinitionId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the decision definition.")
  @JsonProperty(JSON_PROPERTY_DECISION_DEFINITION_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getDecisionDefinitionId() {
    return decisionDefinitionId;
  }


  public void setDecisionDefinitionId(String decisionDefinitionId) {
    this.decisionDefinitionId = decisionDefinitionId;
  }


  public CleanableHistoricDecisionInstanceReportResultDto decisionDefinitionKey(String decisionDefinitionKey) {
    
    this.decisionDefinitionKey = decisionDefinitionKey;
    return this;
  }

   /**
   * The key of the decision definition.
   * @return decisionDefinitionKey
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The key of the decision definition.")
  @JsonProperty(JSON_PROPERTY_DECISION_DEFINITION_KEY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getDecisionDefinitionKey() {
    return decisionDefinitionKey;
  }


  public void setDecisionDefinitionKey(String decisionDefinitionKey) {
    this.decisionDefinitionKey = decisionDefinitionKey;
  }


  public CleanableHistoricDecisionInstanceReportResultDto decisionDefinitionName(String decisionDefinitionName) {
    
    this.decisionDefinitionName = decisionDefinitionName;
    return this;
  }

   /**
   * The name of the decision definition.
   * @return decisionDefinitionName
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The name of the decision definition.")
  @JsonProperty(JSON_PROPERTY_DECISION_DEFINITION_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getDecisionDefinitionName() {
    return decisionDefinitionName;
  }


  public void setDecisionDefinitionName(String decisionDefinitionName) {
    this.decisionDefinitionName = decisionDefinitionName;
  }


  public CleanableHistoricDecisionInstanceReportResultDto decisionDefinitionVersion(Integer decisionDefinitionVersion) {
    
    this.decisionDefinitionVersion = decisionDefinitionVersion;
    return this;
  }

   /**
   * The version of the decision definition.
   * @return decisionDefinitionVersion
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The version of the decision definition.")
  @JsonProperty(JSON_PROPERTY_DECISION_DEFINITION_VERSION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getDecisionDefinitionVersion() {
    return decisionDefinitionVersion;
  }


  public void setDecisionDefinitionVersion(Integer decisionDefinitionVersion) {
    this.decisionDefinitionVersion = decisionDefinitionVersion;
  }


  public CleanableHistoricDecisionInstanceReportResultDto historyTimeToLive(Integer historyTimeToLive) {
    
    this.historyTimeToLive = historyTimeToLive;
    return this;
  }

   /**
   * The history time to live of the decision definition.
   * @return historyTimeToLive
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The history time to live of the decision definition.")
  @JsonProperty(JSON_PROPERTY_HISTORY_TIME_TO_LIVE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getHistoryTimeToLive() {
    return historyTimeToLive;
  }


  public void setHistoryTimeToLive(Integer historyTimeToLive) {
    this.historyTimeToLive = historyTimeToLive;
  }


  public CleanableHistoricDecisionInstanceReportResultDto finishedDecisionInstanceCount(Long finishedDecisionInstanceCount) {
    
    this.finishedDecisionInstanceCount = finishedDecisionInstanceCount;
    return this;
  }

   /**
   * The count of the finished historic decision instances.
   * @return finishedDecisionInstanceCount
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The count of the finished historic decision instances.")
  @JsonProperty(JSON_PROPERTY_FINISHED_DECISION_INSTANCE_COUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getFinishedDecisionInstanceCount() {
    return finishedDecisionInstanceCount;
  }


  public void setFinishedDecisionInstanceCount(Long finishedDecisionInstanceCount) {
    this.finishedDecisionInstanceCount = finishedDecisionInstanceCount;
  }


  public CleanableHistoricDecisionInstanceReportResultDto cleanableDecisionInstanceCount(Long cleanableDecisionInstanceCount) {
    
    this.cleanableDecisionInstanceCount = cleanableDecisionInstanceCount;
    return this;
  }

   /**
   * The count of the cleanable historic decision instances, referring to history time to live.
   * @return cleanableDecisionInstanceCount
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The count of the cleanable historic decision instances, referring to history time to live.")
  @JsonProperty(JSON_PROPERTY_CLEANABLE_DECISION_INSTANCE_COUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getCleanableDecisionInstanceCount() {
    return cleanableDecisionInstanceCount;
  }


  public void setCleanableDecisionInstanceCount(Long cleanableDecisionInstanceCount) {
    this.cleanableDecisionInstanceCount = cleanableDecisionInstanceCount;
  }


  public CleanableHistoricDecisionInstanceReportResultDto tenantId(String tenantId) {
    
    this.tenantId = tenantId;
    return this;
  }

   /**
   * The tenant id of the decision definition.
   * @return tenantId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The tenant id of the decision definition.")
  @JsonProperty(JSON_PROPERTY_TENANT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getTenantId() {
    return tenantId;
  }


  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CleanableHistoricDecisionInstanceReportResultDto cleanableHistoricDecisionInstanceReportResultDto = (CleanableHistoricDecisionInstanceReportResultDto) o;
    return Objects.equals(this.decisionDefinitionId, cleanableHistoricDecisionInstanceReportResultDto.decisionDefinitionId) &&
        Objects.equals(this.decisionDefinitionKey, cleanableHistoricDecisionInstanceReportResultDto.decisionDefinitionKey) &&
        Objects.equals(this.decisionDefinitionName, cleanableHistoricDecisionInstanceReportResultDto.decisionDefinitionName) &&
        Objects.equals(this.decisionDefinitionVersion, cleanableHistoricDecisionInstanceReportResultDto.decisionDefinitionVersion) &&
        Objects.equals(this.historyTimeToLive, cleanableHistoricDecisionInstanceReportResultDto.historyTimeToLive) &&
        Objects.equals(this.finishedDecisionInstanceCount, cleanableHistoricDecisionInstanceReportResultDto.finishedDecisionInstanceCount) &&
        Objects.equals(this.cleanableDecisionInstanceCount, cleanableHistoricDecisionInstanceReportResultDto.cleanableDecisionInstanceCount) &&
        Objects.equals(this.tenantId, cleanableHistoricDecisionInstanceReportResultDto.tenantId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(decisionDefinitionId, decisionDefinitionKey, decisionDefinitionName, decisionDefinitionVersion, historyTimeToLive, finishedDecisionInstanceCount, cleanableDecisionInstanceCount, tenantId);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CleanableHistoricDecisionInstanceReportResultDto {\n");
    sb.append("    decisionDefinitionId: ").append(toIndentedString(decisionDefinitionId)).append("\n");
    sb.append("    decisionDefinitionKey: ").append(toIndentedString(decisionDefinitionKey)).append("\n");
    sb.append("    decisionDefinitionName: ").append(toIndentedString(decisionDefinitionName)).append("\n");
    sb.append("    decisionDefinitionVersion: ").append(toIndentedString(decisionDefinitionVersion)).append("\n");
    sb.append("    historyTimeToLive: ").append(toIndentedString(historyTimeToLive)).append("\n");
    sb.append("    finishedDecisionInstanceCount: ").append(toIndentedString(finishedDecisionInstanceCount)).append("\n");
    sb.append("    cleanableDecisionInstanceCount: ").append(toIndentedString(cleanableDecisionInstanceCount)).append("\n");
    sb.append("    tenantId: ").append(toIndentedString(tenantId)).append("\n");
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

