/* $Id$ */
/* Modified to MCFAuthorizerUtils.java 2015-04-28 Bart Superson */
/**
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements. See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.apache.manifoldcf.elasticsearch;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.ElasticsearchIllegalArgumentException;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.query.*;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.search.RestSearchAction;
import org.elasticsearch.rest.action.support.RestActions;
import org.elasticsearch.search.Scroll;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.fetch.source.FetchSourceContext;
import org.elasticsearch.search.sort.SortOrder;
import org.elasticsearch.search.suggest.SuggestBuilders;
import org.elasticsearch.search.suggest.term.TermSuggestionBuilder;

import java.io.*;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MCFAuthorizerUtils {

  protected static String ALLOW_FIELD_PREFIX = "allow_token_";
  protected static String DENY_FIELD_PREFIX = "deny_token_";

  protected final static String AUTHORITY_BASE_URL = "http://localhost:8345/mcf-authority-service";
  protected final static String FIELD_ALLOW_DOCUMENT = ALLOW_FIELD_PREFIX +"document";
  protected final static String FIELD_DENY_DOCUMENT = DENY_FIELD_PREFIX +"document";
  protected final static String FIELD_ALLOW_PARENT = ALLOW_FIELD_PREFIX +"share";
  protected final static String FIELD_DENY_PARENT = DENY_FIELD_PREFIX +"share";
  protected final static String FIELD_ALLOW_SHARE = ALLOW_FIELD_PREFIX +"parent";
  protected final static String FIELD_DENY_SHARE = DENY_FIELD_PREFIX +"parent";

  /** Special token for null security fields */
  protected static final String NOSECURITY_TOKEN = "__nosecurity__";

  private final static CloseableHttpClient httpClient = HttpClients.createDefault();

  private static final ESLogger log = Loggers.getLogger("MCFAuthorizer");

  public static SearchRequest parseSearchRequestMCF(RestRequest request) throws MCFAuthorizerException {
    SearchRequest searchRequest;
    //if(usernameAndDomain[0]==null) throw new MCFAuthorizerException("Username not passed.");
    if(request.param("u")!=null) {
      String[] authenticatedUserNamesAndDomains = request.param("u").split(",");
      String[] indices = Strings.splitStringByCommaToArray(request.param("index"));
      searchRequest = new SearchRequest(indices);
      boolean isTemplateRequest = request.path().endsWith("/template");

      if(request.hasContent() || request.hasParam("source")) {
        FilterBuilder authorizationFilter = buildAuthorizationFilter(authenticatedUserNamesAndDomains);
        FilteredQueryBuilder filteredQueryBuilder;

        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode modifiedJSON, innerJSON;
        JsonNode requestJSON;

        try {
          requestJSON = objectMapper.readTree(RestActions.getRestContent(request).toBytes());
          if (isTemplateRequest) {
            modifiedJSON = (ObjectNode) requestJSON;
            innerJSON = (ObjectNode)requestJSON.findValue("template");
            filteredQueryBuilder = QueryBuilders.filteredQuery(QueryBuilders.wrapperQuery(innerJSON.findValue("query").toString()), authorizationFilter);
            modifiedJSON.replace("template",innerJSON.set("query", objectMapper.readTree(filteredQueryBuilder.buildAsBytes().toBytes())));
            searchRequest.templateSource(modifiedJSON.toString());
          } else {
            filteredQueryBuilder = QueryBuilders.filteredQuery(QueryBuilders.wrapperQuery(requestJSON.findValue("query").toString()), authorizationFilter);
            modifiedJSON = (ObjectNode) requestJSON;
            modifiedJSON.set("query", objectMapper.readTree(filteredQueryBuilder.buildAsBytes().toBytes()));
            searchRequest.source(modifiedJSON.toString());
          }
        } catch (IOException e) {
            e.printStackTrace();
            throw new MCFAuthorizerException("JSON parser error");
          }
      }

      searchRequest.extraSource(parseSearchSourceMCF(request));
      searchRequest.searchType(request.param("search_type"));
      searchRequest.queryCache(request.paramAsBoolean("query_cache", (Boolean)null));
      String scroll = request.param("scroll");
      if(scroll != null) {
        searchRequest.scroll(new Scroll(TimeValue.parseTimeValue(scroll, (TimeValue)null)));
      }

      searchRequest.types(Strings.splitStringByCommaToArray(request.param("type")));
      searchRequest.routing(request.param("routing"));
      searchRequest.preference(request.param("preference"));
      searchRequest.indicesOptions(IndicesOptions.fromRequest(request, searchRequest.indicesOptions()));
    }
    else {
      searchRequest = RestSearchAction.parseSearchRequest(request);
    }
    return searchRequest;
  }

  public static SearchSourceBuilder parseSearchSourceMCF(RestRequest request) throws MCFAuthorizerException {
    SearchSourceBuilder searchSourceBuilder = null;
    String queryString = request.param("q");
    if(queryString != null) {
      String[] authenticatedUserNamesAndDomains = request.param("u").split(",");
      FilterBuilder authorizationFilter = buildAuthorizationFilter(authenticatedUserNamesAndDomains);
      QueryStringQueryBuilder from = QueryBuilders.queryStringQuery(queryString);
      from.defaultField(request.param("df"));
      from.analyzer(request.param("analyzer"));
      from.analyzeWildcard(request.paramAsBoolean("analyze_wildcard", false));
      from.lowercaseExpandedTerms(request.paramAsBoolean("lowercase_expanded_terms", true));
      from.lenient(request.paramAsBoolean("lenient", (Boolean)null));
      String size = request.param("default_operator");
      if(size != null) {
        if("OR".equals(size)) {
          from.defaultOperator(QueryStringQueryBuilder.Operator.OR);
        } else {
          if(!"AND".equals(size)) {
            throw new ElasticsearchIllegalArgumentException("Unsupported defaultOperator [" + size + "], can either be [OR] or [AND]");
          }

          from.defaultOperator(QueryStringQueryBuilder.Operator.AND);
        }
      }

      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.query(QueryBuilders.filteredQuery(from, authorizationFilter));
    }
    else {
        if(!(request.hasContent() || request.hasParam("source"))){
          if(searchSourceBuilder == null) {
            searchSourceBuilder = new SearchSourceBuilder();
          }
          FilterBuilder authorizationFilter = buildAuthorizationFilter(request.param("u"));
          searchSourceBuilder.query(QueryBuilders.filteredQuery(QueryBuilders.matchAllQuery(),authorizationFilter));
        }
    }

    int var19 = request.paramAsInt("from", -1);
    if(var19 != -1) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.from(var19);
    }

    int var20 = request.paramAsInt("size", -1);
    if(var20 != -1) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.size(var20);
    }

    if(request.hasParam("explain")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.explain(request.paramAsBoolean("explain", (Boolean)null));
    }

    if(request.hasParam("version")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.version(request.paramAsBoolean("version", (Boolean)null));
    }

    if(request.hasParam("timeout")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.timeout(request.paramAsTime("timeout", (TimeValue)null));
    }

    if(request.hasParam("terminate_after")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      int sField = request.paramAsInt("terminate_after", 0);
      if(sField < 0) {
        throw new ElasticsearchIllegalArgumentException("terminateAfter must be > 0");
      }

      if(sField > 0) {
        searchSourceBuilder.terminateAfter(sField);
      }
    }

    String var21 = request.param("fields");
    String suggestField;
    if(var21 != null) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      if(!Strings.hasText(var21)) {
        searchSourceBuilder.noFields();
      } else {
        String[] fetchSourceContext = Strings.splitStringByCommaToArray(var21);
        if(fetchSourceContext != null) {
          String[] sSorts = fetchSourceContext;
          int sIndicesBoost = fetchSourceContext.length;

          for(int sStats = 0; sStats < sIndicesBoost; ++sStats) {
            suggestField = sSorts[sStats];
            searchSourceBuilder.field(suggestField);
          }
        }
      }
    }

    FetchSourceContext var22 = FetchSourceContext.parseFromRestRequest(request);
    if(var22 != null) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.fetchSource(var22);
    }

    if(request.hasParam("track_scores")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.trackScores(request.paramAsBoolean("track_scores", false));
    }

    String var23 = request.param("sort");
    int suggestText;
    String indexName;
    String[] var26;
    if(var23 != null) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      String[] var24 = Strings.splitStringByCommaToArray(var23);
      var26 = var24;
      int var27 = var24.length;

      for(suggestText = 0; suggestText < var27; ++suggestText) {
        String suggestSize = var26[suggestText];
        int suggestMode = suggestSize.lastIndexOf(":");
        if(suggestMode != -1) {
          String divisor = suggestSize.substring(0, suggestMode);
          indexName = suggestSize.substring(suggestMode + 1);
          if("asc".equals(indexName)) {
            searchSourceBuilder.sort(divisor, SortOrder.ASC);
          } else if("desc".equals(indexName)) {
            searchSourceBuilder.sort(divisor, SortOrder.DESC);
          }
        } else {
          searchSourceBuilder.sort(suggestSize);
        }
      }
    }

    String var25 = request.param("indices_boost");
    int var31;
    String var32;
    if(var25 != null) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      var26 = Strings.splitStringByCommaToArray(var25);
      String[] var29 = var26;
      suggestText = var26.length;

      for(var31 = 0; var31 < suggestText; ++var31) {
        var32 = var29[var31];
        int var33 = var32.indexOf(44);
        if(var33 == -1) {
          throw new ElasticsearchIllegalArgumentException("Illegal index boost [" + var32 + "], no \',\'");
        }

        indexName = var32.substring(0, var33);
        String sBoost = var32.substring(var33 + 1);

        try {
          searchSourceBuilder.indexBoost(indexName, Float.parseFloat(sBoost));
        } catch (NumberFormatException var18) {
          throw new ElasticsearchIllegalArgumentException("Illegal index boost [" + var32 + "], boost not a float number");
        }
      }
    }

    String var28 = request.param("stats");
    if(var28 != null) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      searchSourceBuilder.stats(Strings.splitStringByCommaToArray(var28));
    }

    suggestField = request.param("suggest_field");
    if(suggestField != null) {
      String var30 = request.param("suggest_text", queryString);
      var31 = request.paramAsInt("suggest_size", 5);
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }

      var32 = request.param("suggest_mode");
      searchSourceBuilder.suggest().addSuggestion(((TermSuggestionBuilder)((TermSuggestionBuilder)((TermSuggestionBuilder)SuggestBuilders.termSuggestion(suggestField).field(suggestField)).text(var30)).size(var31)).suggestMode(var32));
    }

    return searchSourceBuilder;
  }

  /** Main method for building a filter representing appropriate security.
   *@param authenticatedUserNamesAndDomains is a list of user names and its domains in the form "user@domain".
   *@return the filter builder.
   */
  public static FilterBuilder buildAuthorizationFilter(String[] authenticatedUserNamesAndDomains)
          throws  MCFAuthorizerException{
    Map<String,String> domainMap = new HashMap<String,String>();
    for(String buffer : authenticatedUserNamesAndDomains){
      String[] authenticatedUserNameAndDomain = buffer.split("@", 2);
      String authenticatedUserName = authenticatedUserNameAndDomain[0];
      String authenticatedUserDomain;
      if(authenticatedUserNameAndDomain.length<2) authenticatedUserDomain="";
      else authenticatedUserDomain=authenticatedUserNameAndDomain[1];
      domainMap.put(authenticatedUserDomain, authenticatedUserName);
    }
    return buildAuthorizationFilter(domainMap);
  }


  /** Main method for building a filter representing appropriate security.
   *@param domainMap is a map from MCF authorization domain name to user name,
   * and describes a complete user identity.
   *@return the filter builder.
   */
  public static FilterBuilder buildAuthorizationFilter(Map<String,String> domainMap)
          throws MCFAuthorizerException
  {
    if (AUTHORITY_BASE_URL == null)
      throw new IllegalStateException("Authority base URL required for finding access tokens for a user");

    if (domainMap == null || domainMap.size() == 0)
      throw new IllegalArgumentException("Cannot find user tokens for null user");

    StringBuilder sb = new StringBuilder("[");
    boolean first = true;
    for (String domain : domainMap.keySet())
    {
      if (!first)
        sb.append(",");
      else
        first = false;
      sb.append(domain).append(":").append(domainMap.get(domain));
    }
    sb.append("]");
    log.info("Trying to match docs for user '"+sb.toString()+"'");

    return buildAuthorizationFilter(getAccessTokens(domainMap));
  }

  /** Main method for building a filter representing appropriate security.
   *@param authenticatedUserName is a user name in the form "user@domain".
   *@return the filter builder.
   */
  public static FilterBuilder buildAuthorizationFilter(String authenticatedUserName)
          throws MCFAuthorizerException
  {
    return buildAuthorizationFilter(authenticatedUserName, "");
  }

  /** Main method for building a filter representing appropriate security.
   *@param authenticatedUserName is a user name in the form "user@domain".
   *@param authenticatedUserDomain is the corresponding MCF authorization domain.
   *@return the filter builder.
   */
  public static FilterBuilder buildAuthorizationFilter(String authenticatedUserName, String authenticatedUserDomain)
          throws MCFAuthorizerException
  {
    Map<String,String> domainMap = new HashMap<String,String>();
    domainMap.put(authenticatedUserDomain, authenticatedUserName);
    return buildAuthorizationFilter(domainMap);
  }

  /** Main method for building a filter representing appropriate security.
   *@param userAccessTokens are a set of tokens to use to construct the filter (presumably from mod_authz_annotate, upstream)
   *@return the wrapped query enforcing ManifoldCF security.
   */
  public static FilterBuilder buildAuthorizationFilter(List<String> userAccessTokens)
          throws MCFAuthorizerException
  {
    BoolFilterBuilder bq = new BoolFilterBuilder();

    FilterBuilder allowShareOpen = new TermFilterBuilder(FIELD_ALLOW_SHARE,NOSECURITY_TOKEN);
    FilterBuilder denyShareOpen = new TermFilterBuilder(FIELD_DENY_SHARE,NOSECURITY_TOKEN);
    FilterBuilder allowParentOpen = new TermFilterBuilder(FIELD_ALLOW_PARENT,NOSECURITY_TOKEN);
    FilterBuilder denyParentOpen = new TermFilterBuilder(FIELD_DENY_PARENT,NOSECURITY_TOKEN);
    FilterBuilder allowDocumentOpen = new TermFilterBuilder(FIELD_ALLOW_DOCUMENT,NOSECURITY_TOKEN);
    FilterBuilder denyDocumentOpen = new TermFilterBuilder(FIELD_DENY_DOCUMENT,NOSECURITY_TOKEN);

    if (userAccessTokens == null || userAccessTokens.size() == 0)
    {
      // Only open documents can be included.
      // That query is:
      // (FIELD_ALLOW_SHARE is empty AND FIELD_DENY_SHARE is empty AND FIELD_ALLOW_DOCUMENT is empty AND FIELD_DENY_DOCUMENT is empty)
      // We're trying to map to:  -(FIELD_ALLOW_SHARE:*) , which should be pretty efficient in Solr because it is negated.  If this turns out not to be so, then we should
      // have the SolrConnector inject a special token into these fields when they otherwise would be empty, and we can trivially match on that token.
      bq.must(allowShareOpen);
      bq.must(denyShareOpen);
      bq.must(allowParentOpen);
      bq.must(denyParentOpen);
      bq.must(allowDocumentOpen);
      bq.must(denyDocumentOpen);
    }
    else
    {
      // Extend the query appropriately for each user access token.
      bq.must(calculateCompleteSubquery(FIELD_ALLOW_SHARE, FIELD_DENY_SHARE,allowShareOpen,denyShareOpen,userAccessTokens));
      bq.must(calculateCompleteSubquery(FIELD_ALLOW_DOCUMENT, FIELD_DENY_DOCUMENT,allowDocumentOpen,denyDocumentOpen,userAccessTokens));
      bq.must(calculateCompleteSubquery(FIELD_ALLOW_PARENT, FIELD_DENY_PARENT,allowParentOpen,denyParentOpen,userAccessTokens));
    }

    return bq;
  }

  /** Calculate a complete subclause, representing something like:
   * ((FIELD_ALLOW_SHARE is empty AND FIELD_DENY_SHARE is empty) OR FIELD_ALLOW_SHARE HAS token1 OR FIELD_ALLOW_SHARE HAS token2 ...)
   *     AND FIELD_DENY_SHARE DOESN'T_HAVE token1 AND FIELD_DENY_SHARE DOESN'T_HAVE token2 ...
   */
  private static FilterBuilder calculateCompleteSubquery(String allowField, String denyField, FilterBuilder allowOpen, FilterBuilder denyOpen, List<String> userAccessTokens)
  {
    BoolFilterBuilder bq = new BoolFilterBuilder();
    // No ES equivalent - hope this is done right inside
    //bq.setMaxClauseCount(1000000);

    // Add the empty-acl case
    BoolFilterBuilder subUnprotectedClause = new BoolFilterBuilder();
    subUnprotectedClause.must(allowOpen);
    subUnprotectedClause.must(denyOpen);
    bq.should(subUnprotectedClause);
    for (String accessToken : userAccessTokens)
    {
      bq.should(new TermFilterBuilder(allowField,accessToken));
      bq.mustNot(new TermFilterBuilder(denyField,accessToken));
    }
    return bq;
  }

  /** Get access tokens given a username */
  protected static List<String> getAccessTokens(Map<String,String> domainMap)
          throws MCFAuthorizerException
  {
    try
    {
      StringBuilder urlBuffer = new StringBuilder(AUTHORITY_BASE_URL);
      urlBuffer.append("/UserACLs");
      int i = 0;
      for (String domain : domainMap.keySet())
      {
        if (i == 0)
          urlBuffer.append("?");
        else
          urlBuffer.append("&");
        // For backwards compatibility, handle the singleton case specially
        if (domainMap.size() == 1 && domain.length() == 0)
        {
          urlBuffer.append("username=").append(URLEncoder.encode(domainMap.get(domain),"utf-8"));
        }
        else
        {
          urlBuffer.append("username_").append(Integer.toString(i)).append("=").append(URLEncoder.encode(domainMap.get(domain),"utf-8")).append("&")
                  .append("domain_").append(Integer.toString(i)).append("=").append(URLEncoder.encode(domain,"utf-8"));
        }
        i++;
      }
      String theURL = urlBuffer.toString();
      HttpGet method = new HttpGet(theURL);
      try
      {
        HttpResponse httpResponse = httpClient.execute(method);
        int rval = httpResponse.getStatusLine().getStatusCode();
        if (rval != 200)
        {
          String response = EntityUtils.toString(httpResponse.getEntity(),"utf-8");
          throw new MCFAuthorizerException("Couldn't fetch user's access tokens from ManifoldCF authority service: "+Integer.toString(rval)+"; "+response);
        }
        InputStream is = httpResponse.getEntity().getContent();
        try
        {
          String charSet = ContentType.getOrDefault(httpResponse.getEntity()).getCharset().toString();
          if (charSet == null)
            charSet = "utf-8";
          Reader r = new InputStreamReader(is,charSet);
          try
          {
            BufferedReader br = new BufferedReader(r);
            try
            {
              // Read the tokens, one line at a time.  If any authorities are down, we have no current way to note that, but someday we will.
              List<String> tokenList = new ArrayList<String>();
              while (true)
              {
                String line = br.readLine();
                if (line == null)
                  break;
                if (line.startsWith("TOKEN:"))
                {
                  tokenList.add(line.substring("TOKEN:".length()));
                  log.info(line);
                }
                else {
                  // It probably says something about the state of the authority(s) involved, so log it
                  log.info("Saw authority response "+line);
                }
              }
              return tokenList;
            }
            finally
            {
              br.close();
            }
          }
          finally
          {
            r.close();
          }
        }
        finally
        {
          is.close();
        }
      }
      finally
      {
        method.abort();
      }
    }
    catch (IOException e)
    {
      throw new MCFAuthorizerException("IO exception: "+e.getMessage(),e);
    }
  }

}
