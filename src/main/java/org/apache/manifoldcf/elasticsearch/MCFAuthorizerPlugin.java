/* $Id$ */
/* Modified to MCFAuthorizerPlugin.java 2015-04-28 Bart Superson */
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

import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;

import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.rest.RestModule;

public class MCFAuthorizerPlugin extends AbstractPlugin
{

  private final ESLogger log = Loggers.getLogger(this.getClass());

  public MCFAuthorizerPlugin() {
    log.info("Starting ManifoldCF Authorizer Plugin");
  }

  @Override
  public String name() {
    return "elasticsearch-plugin-mcf";
  }

  @Override
  public String description() {
    return "Plugin to connect elasticsearch with ManifoldCF";
  }

  @Override
  public void processModule(Module module) {
    if (module instanceof RestModule) {
      ((RestModule) module).addRestAction(MCFAuthorizerRestSearchAction.class);
    }
  }
}
