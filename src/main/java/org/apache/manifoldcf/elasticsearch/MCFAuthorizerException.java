/* $Id: AuthorizerException.java 1454684 2013-03-09 11:02:31Z kwright $ */
/* Modified to MCFAuthorizerException.java 2015-04-28 Bart Superson */
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

import org.elasticsearch.ElasticsearchException;

/** This class represents exceptions for authorizing ElasticSearch requests
* to include security.  It is a singleton class whose main public method
* is thread-safe.
*/
public class MCFAuthorizerException extends ElasticsearchException
{
  /** Constructor */
  public MCFAuthorizerException(String message)
  {
    super(message);
  }
  
  public MCFAuthorizerException(String message, Throwable cause)
  {
    super(message,cause);
  }
}
