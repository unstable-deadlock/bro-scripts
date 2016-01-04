
@load base/protocols/http

module HTTP_Entropy;

export {
  redef HTTP::default_capture_password = T;

  # Create an ID for our new stream. By convention, this is
  # called "LOG".
  redef enum Log::ID += { LOG };

  type Info: record {
    ## Timestamp for when the request happened.
    ts:                      time      &log;
    ## Unique ID for the connection.
    uid:                     string    &log;
    ## The connection's 4-tuple of endpoint addresses/ports.
    id:                      conn_id   &log;
    ## Represents the pipelined depth into the connection of this
    ## request/response transaction.
    trans_depth:             count     &log;
    ## Verb used in the HTTP request (GET, POST, HEAD, etc.).
    method:                  string    &log &optional;
    ## Value of the HOST header.
    host:                    string    &log &optional;
    ## URI used in the request.
    uri:                     string    &log &optional;
    ## The entropy of the URI used in the request.
    uri_entropy:             double    &log &optional;
    ## Value of the "referer" header.  The comment is deliberately
    ## misspelled like the standard declares, but the name used here
    ## is "referrer" spelled correctly.
    referrer:                string    &log &optional;
    ## Value of the User-Agent header from the client.
    user_agent:              string    &log &optional;
    ## Actual uncompressed content size of the data transferred from
    ## the client.
    request_body_len:        count     &log &default=0;
    ## Actual uncompressed content size of the data transferred from
    ## the server.
    response_body_len:       count     &log &default=0;
    ## Status code returned by the server.
    status_code:             count     &log &optional;
    ## Status message returned by the server.
    status_msg:              string    &log &optional;
    ## Last seen 1xx informational reply code returned by the server.
    info_code:               count     &log &optional;
    ## Last seen 1xx informational reply message returned by the server.
    info_msg:                string    &log &optional;
    ## Filename given in the Content-Disposition header sent by the
    ## server.
    filename:                string    &log &optional;
    ## Username if basic-auth is performed for the request.
    username:                string    &log &optional;
    ## Password if basic-auth is performed for the request.
    password:                string    &log &optional;
    ## All of the headers that may indicate if the request was proxied.
    proxied:                 set[string] &log &optional;
  };
}

# Optionally, we can add a new field to the connection record so that
# the data we are logging (our "Info" record) will be easily
# accessible in a variety of event handlers.
redef record connection += {
  # By convention, the name of this new field is the lowercase name
  # of the module.
  entropy: Info &optional;
};

# This event is handled at a priority higher than zero so that if
# users modify this stream in another script, they can do so at the
# default priority of zero.
event bro_init() &priority=5
{
  # Create the stream. This adds a default filter automatically.
  Log::create_stream(HTTP_Entropy::LOG, [$columns=Info, $path="http_entropy"]);
}
    
event HTTP::log_http(http: HTTP::Info) 
{
	#print http;
  
  local rec: HTTP_Entropy::Info;
  rec = [$ts = network_time(), 
        $uid = http$uid, 
        $id = http$id,
        $trans_depth = http$trans_depth];

  if (http?$method) {rec$method = http$method;} 
  if (http?$host) {rec$host = http$host;}

  if (http?$uri) 
  {
    rec$uri = http$uri;
    rec$uri_entropy = find_entropy(rec$uri)$entropy;
  }
    
  if (http?$referrer) {rec$referrer = http$referrer;}
  if (http?$user_agent) {rec$user_agent = http$user_agent;}
  if (http?$request_body_len) {rec$request_body_len = http$request_body_len;}
  if (http?$response_body_len) {rec$response_body_len = http$response_body_len;}
  if (http?$status_code) {rec$status_code = http$status_code;}
  if (http?$status_msg) {rec$status_msg = http$status_msg;}
  if (http?$info_code) {rec$info_code = http$info_code;}
  if (http?$info_msg) {rec$info_msg = http$info_msg;}
  if (http?$filename) {rec$filename = http$filename;}
  if (http?$username) {rec$username = http$username;}
  if (http?$password) {rec$password = http$password;}
  if (http?$proxied) {rec$proxied = http$proxied;}

  #print http;
  #print rec;
  #print "";
  Log::write(HTTP_Entropy::LOG, rec);
}
