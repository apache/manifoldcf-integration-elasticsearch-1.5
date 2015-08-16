/* $Id$ */
/* Modified to MCFAuthorizerRestSearchAction.java 2015-04-28 Bart Superson */
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

import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.*;
import org.elasticsearch.rest.action.search.RestSearchAction;
import org.elasticsearch.rest.action.support.RestStatusToXContentListener;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.elasticsearch.ElasticsearchIllegalArgumentException;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.query.*;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.support.RestActions;
import org.elasticsearch.search.Scroll;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.fetch.source.FetchSourceContext;
import org.elasticsearch.search.sort.SortOrder;
import org.elasticsearch.search.suggest.SuggestBuilders;
import org.elasticsearch.search.suggest.term.TermSuggestionBuilder;

import java.io.*;

public class MCFAuthorizerRestSearchAction extends RestSearchAction {

  protected final MCFAuthorizer authorizer;
  
  @Inject
  public MCFAuthorizerRestSearchAction(Settings settings, final RestController restController, Client client) {
    super(settings,restController,client);
    final MCFConfigurationParameters conf = new MCFConfigurationParameters(settings);
    authorizer = new MCFAuthorizer(conf);
  }

  @Override
  public void handleRequest(RestRequest request, RestChannel channel, Client client) {
    SearchRequest searchRequest = parseSearchRequestMCF(request);
    searchRequest.listenerThreaded(false);
    client.search(searchRequest, new RestStatusToXContentListener(channel));
  }
  
  protected SearchRequest parseSearchRequestMCF(final RestRequest request) throws MCFAuthorizerException {
    SearchRequest searchRequest;
    if(request.param("u")!=null) {
      String[] authenticatedUserNamesAndDomains = request.param("u").split(",");
      String[] indices = Strings.splitStringByCommaToArray(request.param("index"));
      searchRequest = new SearchRequest(indices);
      boolean isTemplateRequest = request.path().endsWith("/template");

      if(request.hasContent() || request.hasParam("source")) {
        FilterBuilder authorizationFilter = authorizer.buildAuthorizationFilter(authenticatedUserNamesAndDomains);
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

  protected SearchSourceBuilder parseSearchSourceMCF(final RestRequest request) throws MCFAuthorizerException {
    SearchSourceBuilder searchSourceBuilder = null;
    String queryString = request.param("q");
    if(queryString != null) {
      String[] authenticatedUserNamesAndDomains = request.param("u").split(",");
      FilterBuilder authorizationFilter = authorizer.buildAuthorizationFilter(authenticatedUserNamesAndDomains);
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
          FilterBuilder authorizationFilter = authorizer.buildAuthorizationFilter(request.param("u"));
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

}
