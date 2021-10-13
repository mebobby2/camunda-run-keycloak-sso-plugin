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
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * AuthenticationResult
 */
@JsonPropertyOrder({
  AuthenticationResult.JSON_PROPERTY_AUTHENTICATED_USER,
  AuthenticationResult.JSON_PROPERTY_IS_AUTHENTICATED,
  AuthenticationResult.JSON_PROPERTY_TENANTS,
  AuthenticationResult.JSON_PROPERTY_GROUPS
})
@JsonTypeName("AuthenticationResult")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2021-10-13T17:49:51.183809+02:00[Europe/Berlin]")
public class AuthenticationResult {
  public static final String JSON_PROPERTY_AUTHENTICATED_USER = "authenticatedUser";
  private String authenticatedUser;

  public static final String JSON_PROPERTY_IS_AUTHENTICATED = "isAuthenticated";
  private Boolean isAuthenticated;

  public static final String JSON_PROPERTY_TENANTS = "tenants";
  private List<String> tenants = null;

  public static final String JSON_PROPERTY_GROUPS = "groups";
  private List<String> groups = null;


  public AuthenticationResult authenticatedUser(String authenticatedUser) {
    
    this.authenticatedUser = authenticatedUser;
    return this;
  }

   /**
   * An id of authenticated user.
   * @return authenticatedUser
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An id of authenticated user.")
  @JsonProperty(JSON_PROPERTY_AUTHENTICATED_USER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getAuthenticatedUser() {
    return authenticatedUser;
  }


  public void setAuthenticatedUser(String authenticatedUser) {
    this.authenticatedUser = authenticatedUser;
  }


  public AuthenticationResult isAuthenticated(Boolean isAuthenticated) {
    
    this.isAuthenticated = isAuthenticated;
    return this;
  }

   /**
   * A flag indicating if user is authenticated.
   * @return isAuthenticated
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A flag indicating if user is authenticated.")
  @JsonProperty(JSON_PROPERTY_IS_AUTHENTICATED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getIsAuthenticated() {
    return isAuthenticated;
  }


  public void setIsAuthenticated(Boolean isAuthenticated) {
    this.isAuthenticated = isAuthenticated;
  }


  public AuthenticationResult tenants(List<String> tenants) {
    
    this.tenants = tenants;
    return this;
  }

  public AuthenticationResult addTenantsItem(String tenantsItem) {
    if (this.tenants == null) {
      this.tenants = new ArrayList<>();
    }
    this.tenants.add(tenantsItem);
    return this;
  }

   /**
   * Will be null.
   * @return tenants
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Will be null.")
  @JsonProperty(JSON_PROPERTY_TENANTS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getTenants() {
    return tenants;
  }


  public void setTenants(List<String> tenants) {
    this.tenants = tenants;
  }


  public AuthenticationResult groups(List<String> groups) {
    
    this.groups = groups;
    return this;
  }

  public AuthenticationResult addGroupsItem(String groupsItem) {
    if (this.groups == null) {
      this.groups = new ArrayList<>();
    }
    this.groups.add(groupsItem);
    return this;
  }

   /**
   * Will be null.
   * @return groups
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Will be null.")
  @JsonProperty(JSON_PROPERTY_GROUPS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getGroups() {
    return groups;
  }


  public void setGroups(List<String> groups) {
    this.groups = groups;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthenticationResult authenticationResult = (AuthenticationResult) o;
    return Objects.equals(this.authenticatedUser, authenticationResult.authenticatedUser) &&
        Objects.equals(this.isAuthenticated, authenticationResult.isAuthenticated) &&
        Objects.equals(this.tenants, authenticationResult.tenants) &&
        Objects.equals(this.groups, authenticationResult.groups);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authenticatedUser, isAuthenticated, tenants, groups);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthenticationResult {\n");
    sb.append("    authenticatedUser: ").append(toIndentedString(authenticatedUser)).append("\n");
    sb.append("    isAuthenticated: ").append(toIndentedString(isAuthenticated)).append("\n");
    sb.append("    tenants: ").append(toIndentedString(tenants)).append("\n");
    sb.append("    groups: ").append(toIndentedString(groups)).append("\n");
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

