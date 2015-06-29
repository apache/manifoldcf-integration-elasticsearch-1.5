/* $Id: MCFAuthorizer.java 1571011 2014-02-23 13:46:13Z kwright $ */
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

 /*
    New parseSearchRequestMCF function added in utils to parse RestRequest.
    There are also problems with security using JavaSearchAPI, because it doesn't implements setParam function
    to set username param, but this can be ommited using JavaScriptAPI, which allows to do that.
    Security filter can be also applied in this class but there is a problem with proper extraSource parsing.
    There is also a possibility to create service, inject RestController into it, register RestFilter in it, which
    should be used only if request handled by RestSearchAction and replace query from this request with
    the same query wrapped by security filter.
 */

public class MCFAuthorizerRestSearchAction extends RestSearchAction {

  @Inject
  public MCFAuthorizerRestSearchAction(Settings settings, final RestController restController, Client client) {
    super(settings,restController,client);
  }

  @Override
  public void handleRequest(RestRequest request, RestChannel channel, Client client) {
    SearchRequest searchRequest = MCFAuthorizerUtils.parseSearchRequestMCF(request);
    searchRequest.listenerThreaded(false);
    client.search(searchRequest, new RestStatusToXContentListener(channel));
  }
}
