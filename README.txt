# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Compatibility
------------

This version of this component is fully functional with Apache ManifoldCF 1.6 and
above and with Elasticsearch 1.5.x.

Instructions for Building Apache ManifoldCF Plugin for Elastic Search from Source
-----------------------------------------------------------------------------

1. Download the Java SE 6 JDK (Java Development Kit), or greater, from
   http://www.oracle.com/technetwork/java/index.html.
   You will need the JDK installed, and the %JAVA_HOME%\bin directory included
   on your command path.  To test this, issue a "java -version" command from your
   shell and verify that the Java version is 1.6 or greater.

2. Download and install Maven 2.2.1 or later.  Maven installation and configuration
   instructions can be found here:

http://maven.apache.org/run-maven/index.html

3. Build packages

Execute the following command in order to build the JAR packages and install 
them to the local repository:

mvn clean install

The JAR packages can be found in the target folder:

target/elasticsearch-1.5-plugin-mcf-<VERSION>-jar-with-dependencies.jar

... where <VERSION> is the release version

4. Building distribution assemblies 

Execute the following command in order to build the distribution assemblies

mvn package assembly:assembly

5. Fix EOL in source files

Fix the archive files so the source files have the correct EOL settings:

mvn antrun:run

Usage
---------

1) Configure the plugin using Elasticsearch config file (elasticsearch.yml) by providing these parameters:

    "mcf.authority_service_base_url" - the URL to the ManifoldCF Authority Service (default: "http://localhost:8345/mcf-authority-service")
    "mcf.http.connection_timeout" - HTTP client connection timeout (default: 60000)
    "mcf.http.socket_timeout" - HTTP client socket timeout (default: 300000)
    "mcf.allow_field_prefix" - allow field prefix (default: "allow_token_")
    "mcf.deny_field_prefix" - deny field prefix (default: "deny_token_")
    "mcf.http.connection_pool_size" - HTTP client connection pool size (default: 50).


2) Invoke ElasticSearch in the following manner to filter documents with security:

http://<ElasticSearch_Host_And_Port/<index_name>/_search?u=<user>

Or, optionally:

http://<ElasticSearch_Host_And_Port/<index_name>/_search?u=<user>@<domain>
http://<ElasticSearch_Host_And_Port/<index_name>/_search?u=<user1>@<domain1>,<user2>@<domain2>...

If the "u" parameter is not provided, no security filtering will be done.


3) Integrate this plugin with your Controller in the following way:

@RestController
@RequestMapping("/search")
public class SearchController {

    private SearchService searchService;

    @Autowired
    public SearchController(SearchService searchService){
        this.searchService = searchService;
    }

    @RequestMapping(value="**", method = RequestMethod.POST)
        public ResponseEntity<String> forwardQuery(HttpServletRequest request) throws ServletException, IOException {
        try {
            return new ResponseEntity<>(searchService.search(request),new HttpHeaders(),HttpStatus.OK);
        } catch (IOException e) {
            return new ResponseEntity<>( "IO Problem: " + e.getMessage(),new HttpHeaders(),HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }
}

4) To integrate this plugin to authorize automatically with your Service, use:

@Service
public class SearchService {

    private final CloseableHttpClient httpClient = HttpClients.createDefault();

    public String search(HttpServletRequest request) throws IOException {
        String jsonBody = IOUtils.toString(request.getInputStream());
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String forwardTo = "http://<ElasticSearch_Host_And_Port>" + request.getServletPath() + "?u=" + username;
        forwardTo = forwardTo.replace("/search", "");
        HttpPost post = new HttpPost(forwardTo);
        post.setEntity(new StringEntity(jsonBody));
        HttpResponse httpResponse = httpClient.execute(post);
        int rval = httpResponse.getStatusLine().getStatusCode();

        if (rval != 200)
        {
            String response = EntityUtils.toString(httpResponse.getEntity(), "utf-8");
            throw new IOException(" Connection problem: " + Integer.toString(rval)+"; " + response);
        }

        InputStream is = httpResponse.getEntity().getContent();

        return IOUtils.toString(is);
    }
}


Licensing
---------

Apache ManifoldCF Plugin for Elastic Search 1.5 is licensed under the
Apache License 2.0. See the files called LICENSE.txt and NOTICE.txt
for more information.

Cryptographic Software Notice
-----------------------------

This distribution may include software that has been designed for use
with cryptographic software. The country in which you currently reside
may have restrictions on the import, possession, use, and/or re-export
to another country, of encryption software. BEFORE using any encryption
software, please check your country's laws, regulations and policies
concerning the import, possession, or use, and re-export of encryption
software, to see if this is permitted. See <http://www.wassenaar.org/>
for more information.

The U.S. Government Department of Commerce, Bureau of Industry and
Security (BIS), has classified this software as Export Commodity
Control Number (ECCN) 5D002.C.1, which includes information security
software using or performing cryptographic functions with asymmetric
algorithms. The form and manner of this Apache Software Foundation
distribution makes it eligible for export under the License Exception
ENC Technology Software Unrestricted (TSU) exception (see the BIS
Export Administration Regulations, Section 740.13) for both object
code and source code.

The following provides more details on the included software that
may be subject to export controls on cryptographic software:

  The Apache ManifoldCF Plugin for Elastic Search does not include any
  implementation or usage of cryptographic software at this time.
  
Contact
-------

  o For general information visit the main project site at
    http://manifoldcf.apache.org

