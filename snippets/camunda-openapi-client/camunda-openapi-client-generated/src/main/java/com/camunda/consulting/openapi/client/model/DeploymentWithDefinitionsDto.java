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
import com.camunda.consulting.openapi.client.model.AtomLink;
import com.camunda.consulting.openapi.client.model.CaseDefinitionDto;
import com.camunda.consulting.openapi.client.model.DecisionDefinitionDto;
import com.camunda.consulting.openapi.client.model.DecisionRequirementsDefinitionDto;
import com.camunda.consulting.openapi.client.model.DeploymentDto;
import com.camunda.consulting.openapi.client.model.DeploymentWithDefinitionsDtoAllOf;
import com.camunda.consulting.openapi.client.model.ProcessDefinitionDto;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * DeploymentWithDefinitionsDto
 */
@JsonPropertyOrder({
  DeploymentWithDefinitionsDto.JSON_PROPERTY_DEPLOYED_PROCESS_DEFINITIONS,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_DEPLOYED_DECISION_DEFINITIONS,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_DEPLOYED_DECISION_REQUIREMENTS_DEFINITIONS,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_DEPLOYED_CASE_DEFINITIONS,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_ID,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_TENANT_ID,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_DEPLOYMENT_TIME,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_SOURCE,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_NAME,
  DeploymentWithDefinitionsDto.JSON_PROPERTY_LINKS
})
@JsonTypeName("DeploymentWithDefinitionsDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class DeploymentWithDefinitionsDto {
  public static final String JSON_PROPERTY_DEPLOYED_PROCESS_DEFINITIONS = "deployedProcessDefinitions";
  private Map<String, ProcessDefinitionDto> deployedProcessDefinitions = null;

  public static final String JSON_PROPERTY_DEPLOYED_DECISION_DEFINITIONS = "deployedDecisionDefinitions";
  private Map<String, DecisionDefinitionDto> deployedDecisionDefinitions = null;

  public static final String JSON_PROPERTY_DEPLOYED_DECISION_REQUIREMENTS_DEFINITIONS = "deployedDecisionRequirementsDefinitions";
  private Map<String, DecisionRequirementsDefinitionDto> deployedDecisionRequirementsDefinitions = null;

  public static final String JSON_PROPERTY_DEPLOYED_CASE_DEFINITIONS = "deployedCaseDefinitions";
  private Map<String, CaseDefinitionDto> deployedCaseDefinitions = null;

  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_TENANT_ID = "tenantId";
  private String tenantId;

  public static final String JSON_PROPERTY_DEPLOYMENT_TIME = "deploymentTime";
  private OffsetDateTime deploymentTime;

  public static final String JSON_PROPERTY_SOURCE = "source";
  private String source;

  public static final String JSON_PROPERTY_NAME = "name";
  private String name;

  public static final String JSON_PROPERTY_LINKS = "links";
  private List<AtomLink> links = null;


  public DeploymentWithDefinitionsDto deployedProcessDefinitions(Map<String, ProcessDefinitionDto> deployedProcessDefinitions) {
    
    this.deployedProcessDefinitions = deployedProcessDefinitions;
    return this;
  }

  public DeploymentWithDefinitionsDto putDeployedProcessDefinitionsItem(String key, ProcessDefinitionDto deployedProcessDefinitionsItem) {
    if (this.deployedProcessDefinitions == null) {
      this.deployedProcessDefinitions = new HashMap<>();
    }
    this.deployedProcessDefinitions.put(key, deployedProcessDefinitionsItem);
    return this;
  }

   /**
   * A JSON Object containing a property for each of the process definitions, which are successfully deployed with that deployment. The key is the process definition id, the value is a JSON Object corresponding to the process definition.
   * @return deployedProcessDefinitions
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A JSON Object containing a property for each of the process definitions, which are successfully deployed with that deployment. The key is the process definition id, the value is a JSON Object corresponding to the process definition.")
  @JsonProperty(JSON_PROPERTY_DEPLOYED_PROCESS_DEFINITIONS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, ProcessDefinitionDto> getDeployedProcessDefinitions() {
    return deployedProcessDefinitions;
  }


  public void setDeployedProcessDefinitions(Map<String, ProcessDefinitionDto> deployedProcessDefinitions) {
    this.deployedProcessDefinitions = deployedProcessDefinitions;
  }


  public DeploymentWithDefinitionsDto deployedDecisionDefinitions(Map<String, DecisionDefinitionDto> deployedDecisionDefinitions) {
    
    this.deployedDecisionDefinitions = deployedDecisionDefinitions;
    return this;
  }

  public DeploymentWithDefinitionsDto putDeployedDecisionDefinitionsItem(String key, DecisionDefinitionDto deployedDecisionDefinitionsItem) {
    if (this.deployedDecisionDefinitions == null) {
      this.deployedDecisionDefinitions = new HashMap<>();
    }
    this.deployedDecisionDefinitions.put(key, deployedDecisionDefinitionsItem);
    return this;
  }

   /**
   * A JSON Object containing a property for each of the decision definitions, which are successfully deployed with that deployment. The key is the decision definition id, the value is a JSON Object corresponding to the decision definition.
   * @return deployedDecisionDefinitions
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A JSON Object containing a property for each of the decision definitions, which are successfully deployed with that deployment. The key is the decision definition id, the value is a JSON Object corresponding to the decision definition.")
  @JsonProperty(JSON_PROPERTY_DEPLOYED_DECISION_DEFINITIONS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, DecisionDefinitionDto> getDeployedDecisionDefinitions() {
    return deployedDecisionDefinitions;
  }


  public void setDeployedDecisionDefinitions(Map<String, DecisionDefinitionDto> deployedDecisionDefinitions) {
    this.deployedDecisionDefinitions = deployedDecisionDefinitions;
  }


  public DeploymentWithDefinitionsDto deployedDecisionRequirementsDefinitions(Map<String, DecisionRequirementsDefinitionDto> deployedDecisionRequirementsDefinitions) {
    
    this.deployedDecisionRequirementsDefinitions = deployedDecisionRequirementsDefinitions;
    return this;
  }

  public DeploymentWithDefinitionsDto putDeployedDecisionRequirementsDefinitionsItem(String key, DecisionRequirementsDefinitionDto deployedDecisionRequirementsDefinitionsItem) {
    if (this.deployedDecisionRequirementsDefinitions == null) {
      this.deployedDecisionRequirementsDefinitions = new HashMap<>();
    }
    this.deployedDecisionRequirementsDefinitions.put(key, deployedDecisionRequirementsDefinitionsItem);
    return this;
  }

   /**
   * A JSON Object containing a property for each of the decision requirements definitions, which are successfully deployed with that deployment. The key is the decision requirements definition id, the value is a JSON Object corresponding to the decision requirements definition.
   * @return deployedDecisionRequirementsDefinitions
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A JSON Object containing a property for each of the decision requirements definitions, which are successfully deployed with that deployment. The key is the decision requirements definition id, the value is a JSON Object corresponding to the decision requirements definition.")
  @JsonProperty(JSON_PROPERTY_DEPLOYED_DECISION_REQUIREMENTS_DEFINITIONS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, DecisionRequirementsDefinitionDto> getDeployedDecisionRequirementsDefinitions() {
    return deployedDecisionRequirementsDefinitions;
  }


  public void setDeployedDecisionRequirementsDefinitions(Map<String, DecisionRequirementsDefinitionDto> deployedDecisionRequirementsDefinitions) {
    this.deployedDecisionRequirementsDefinitions = deployedDecisionRequirementsDefinitions;
  }


  public DeploymentWithDefinitionsDto deployedCaseDefinitions(Map<String, CaseDefinitionDto> deployedCaseDefinitions) {
    
    this.deployedCaseDefinitions = deployedCaseDefinitions;
    return this;
  }

  public DeploymentWithDefinitionsDto putDeployedCaseDefinitionsItem(String key, CaseDefinitionDto deployedCaseDefinitionsItem) {
    if (this.deployedCaseDefinitions == null) {
      this.deployedCaseDefinitions = new HashMap<>();
    }
    this.deployedCaseDefinitions.put(key, deployedCaseDefinitionsItem);
    return this;
  }

   /**
   * A JSON Object containing a property for each of the case definitions, which are successfully deployed with that deployment. The key is the case definition id, the value is a JSON Object corresponding to the case definition.
   * @return deployedCaseDefinitions
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A JSON Object containing a property for each of the case definitions, which are successfully deployed with that deployment. The key is the case definition id, the value is a JSON Object corresponding to the case definition.")
  @JsonProperty(JSON_PROPERTY_DEPLOYED_CASE_DEFINITIONS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, CaseDefinitionDto> getDeployedCaseDefinitions() {
    return deployedCaseDefinitions;
  }


  public void setDeployedCaseDefinitions(Map<String, CaseDefinitionDto> deployedCaseDefinitions) {
    this.deployedCaseDefinitions = deployedCaseDefinitions;
  }


  public DeploymentWithDefinitionsDto id(String id) {
    
    this.id = id;
    return this;
  }

   /**
   * The id of the deployment.
   * @return id
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the deployment.")
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getId() {
    return id;
  }


  public void setId(String id) {
    this.id = id;
  }


  public DeploymentWithDefinitionsDto tenantId(String tenantId) {
    
    this.tenantId = tenantId;
    return this;
  }

   /**
   * The tenant id of the deployment.
   * @return tenantId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The tenant id of the deployment.")
  @JsonProperty(JSON_PROPERTY_TENANT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getTenantId() {
    return tenantId;
  }


  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }


  public DeploymentWithDefinitionsDto deploymentTime(OffsetDateTime deploymentTime) {
    
    this.deploymentTime = deploymentTime;
    return this;
  }

   /**
   * The time when the deployment was created.
   * @return deploymentTime
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The time when the deployment was created.")
  @JsonProperty(JSON_PROPERTY_DEPLOYMENT_TIME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public OffsetDateTime getDeploymentTime() {
    return deploymentTime;
  }


  public void setDeploymentTime(OffsetDateTime deploymentTime) {
    this.deploymentTime = deploymentTime;
  }


  public DeploymentWithDefinitionsDto source(String source) {
    
    this.source = source;
    return this;
  }

   /**
   * The source of the deployment.
   * @return source
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The source of the deployment.")
  @JsonProperty(JSON_PROPERTY_SOURCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getSource() {
    return source;
  }


  public void setSource(String source) {
    this.source = source;
  }


  public DeploymentWithDefinitionsDto name(String name) {
    
    this.name = name;
    return this;
  }

   /**
   * The name of the deployment.
   * @return name
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The name of the deployment.")
  @JsonProperty(JSON_PROPERTY_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getName() {
    return name;
  }


  public void setName(String name) {
    this.name = name;
  }


  public DeploymentWithDefinitionsDto links(List<AtomLink> links) {
    
    this.links = links;
    return this;
  }

  public DeploymentWithDefinitionsDto addLinksItem(AtomLink linksItem) {
    if (this.links == null) {
      this.links = new ArrayList<>();
    }
    this.links.add(linksItem);
    return this;
  }

   /**
   * The links associated to this resource, with &#x60;method&#x60;, &#x60;href&#x60; and &#x60;rel&#x60;.
   * @return links
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The links associated to this resource, with `method`, `href` and `rel`.")
  @JsonProperty(JSON_PROPERTY_LINKS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<AtomLink> getLinks() {
    return links;
  }


  public void setLinks(List<AtomLink> links) {
    this.links = links;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DeploymentWithDefinitionsDto deploymentWithDefinitionsDto = (DeploymentWithDefinitionsDto) o;
    return Objects.equals(this.deployedProcessDefinitions, deploymentWithDefinitionsDto.deployedProcessDefinitions) &&
        Objects.equals(this.deployedDecisionDefinitions, deploymentWithDefinitionsDto.deployedDecisionDefinitions) &&
        Objects.equals(this.deployedDecisionRequirementsDefinitions, deploymentWithDefinitionsDto.deployedDecisionRequirementsDefinitions) &&
        Objects.equals(this.deployedCaseDefinitions, deploymentWithDefinitionsDto.deployedCaseDefinitions) &&
        Objects.equals(this.id, deploymentWithDefinitionsDto.id) &&
        Objects.equals(this.tenantId, deploymentWithDefinitionsDto.tenantId) &&
        Objects.equals(this.deploymentTime, deploymentWithDefinitionsDto.deploymentTime) &&
        Objects.equals(this.source, deploymentWithDefinitionsDto.source) &&
        Objects.equals(this.name, deploymentWithDefinitionsDto.name) &&
        Objects.equals(this.links, deploymentWithDefinitionsDto.links);
  }

  @Override
  public int hashCode() {
    return Objects.hash(deployedProcessDefinitions, deployedDecisionDefinitions, deployedDecisionRequirementsDefinitions, deployedCaseDefinitions, id, tenantId, deploymentTime, source, name, links);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DeploymentWithDefinitionsDto {\n");
    sb.append("    deployedProcessDefinitions: ").append(toIndentedString(deployedProcessDefinitions)).append("\n");
    sb.append("    deployedDecisionDefinitions: ").append(toIndentedString(deployedDecisionDefinitions)).append("\n");
    sb.append("    deployedDecisionRequirementsDefinitions: ").append(toIndentedString(deployedDecisionRequirementsDefinitions)).append("\n");
    sb.append("    deployedCaseDefinitions: ").append(toIndentedString(deployedCaseDefinitions)).append("\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    tenantId: ").append(toIndentedString(tenantId)).append("\n");
    sb.append("    deploymentTime: ").append(toIndentedString(deploymentTime)).append("\n");
    sb.append("    source: ").append(toIndentedString(source)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    links: ").append(toIndentedString(links)).append("\n");
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

