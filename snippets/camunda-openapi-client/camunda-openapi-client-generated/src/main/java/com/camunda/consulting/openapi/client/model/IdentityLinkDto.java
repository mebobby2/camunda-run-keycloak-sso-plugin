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
 * IdentityLinkDto
 */
@JsonPropertyOrder({
  IdentityLinkDto.JSON_PROPERTY_USER_ID,
  IdentityLinkDto.JSON_PROPERTY_GROUP_ID,
  IdentityLinkDto.JSON_PROPERTY_TYPE
})
@JsonTypeName("IdentityLinkDto")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class IdentityLinkDto {
  public static final String JSON_PROPERTY_USER_ID = "userId";
  private String userId;

  public static final String JSON_PROPERTY_GROUP_ID = "groupId";
  private String groupId;

  public static final String JSON_PROPERTY_TYPE = "type";
  private String type;


  public IdentityLinkDto userId(String userId) {
    
    this.userId = userId;
    return this;
  }

   /**
   * The id of the user participating in this link. Either &#x60;userId&#x60; or &#x60;groupId&#x60; is set.
   * @return userId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the user participating in this link. Either `userId` or `groupId` is set.")
  @JsonProperty(JSON_PROPERTY_USER_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getUserId() {
    return userId;
  }


  public void setUserId(String userId) {
    this.userId = userId;
  }


  public IdentityLinkDto groupId(String groupId) {
    
    this.groupId = groupId;
    return this;
  }

   /**
   * The id of the group participating in this link. Either &#x60;groupId&#x60; or &#x60;userId&#x60; is set.
   * @return groupId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The id of the group participating in this link. Either `groupId` or `userId` is set.")
  @JsonProperty(JSON_PROPERTY_GROUP_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getGroupId() {
    return groupId;
  }


  public void setGroupId(String groupId) {
    this.groupId = groupId;
  }


  public IdentityLinkDto type(String type) {
    
    this.type = type;
    return this;
  }

   /**
   * The type of the identity link. The value of the this property can be user-defined. The Process Engine provides three pre-defined Identity Link &#x60;type&#x60;s:  * &#x60;candidate&#x60; * &#x60;assignee&#x60; - reserved for the task assignee * &#x60;owner&#x60; - reserved for the task owner  **Note**: When adding or removing an Identity Link, the &#x60;type&#x60; property must be defined.
   * @return type
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(required = true, value = "The type of the identity link. The value of the this property can be user-defined. The Process Engine provides three pre-defined Identity Link `type`s:  * `candidate` * `assignee` - reserved for the task assignee * `owner` - reserved for the task owner  **Note**: When adding or removing an Identity Link, the `type` property must be defined.")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.ALWAYS)

  public String getType() {
    return type;
  }


  public void setType(String type) {
    this.type = type;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    IdentityLinkDto identityLinkDto = (IdentityLinkDto) o;
    return Objects.equals(this.userId, identityLinkDto.userId) &&
        Objects.equals(this.groupId, identityLinkDto.groupId) &&
        Objects.equals(this.type, identityLinkDto.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(userId, groupId, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class IdentityLinkDto {\n");
    sb.append("    userId: ").append(toIndentedString(userId)).append("\n");
    sb.append("    groupId: ").append(toIndentedString(groupId)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
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

