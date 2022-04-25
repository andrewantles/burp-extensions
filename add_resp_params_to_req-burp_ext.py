import json
import datetime
import re
from java.io import PrintWriter
from burp import IBurpExtender, IBurpExtenderCallbacks, ISessionHandlingAction
 
class BurpExtender(IBurpExtender, ISessionHandlingAction):
 
    NAME = "Body Token to Request -RegEx"

    '''
        This extension was modified from the one found in the following blog posts:
            https://twelvesec.com/2017/05/05/authorization-token-manipulation/
            https://huntforbug.io/manipulating-authorization-token-using-burp-suite/
       
        This is for use with Burp macros. 
        The macro needs to end with the response that contains the needed parameter(s).
        This extension then retrieves the parameter(s) from the JSON response body.
        Create a session handling rule that runs the macro and then invokes this extension.
        The extension replaces the parameter/header in the next request.
        
        Biggest area for improvement is that a ton of work is being done in the performAction
        method. This method is required, though readability would improve if some of the
        work being done within could be abstracted out into other methods.
    '''
    
    def registerExtenderCallbacks(self, callbacks):
 
        # Make errors more readable and required for debugger burp-exceptions
        sys.stdout = callbacks.getStdout()
        # reference our callback objects
        self.callbacks = callbacks
        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()
        # Set the name of the extension fron NAME variable above
        callbacks.setExtensionName(self.NAME)
        # Register the session
        self.callbacks.registerSessionHandlingAction(self)   
        # Use PrintWriter for all output
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        #self.stderr = PrintWriter(callbacks.getStdout(), True)
        self.stdout.println("Bearer Authorization Token \n")
        self.stdout.println('starting at time : {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
        self.stdout.println("-----------------------------------------------------------------\n\n")
        return
   
    def getActionName(self):
        return self.NAME
    
    def performAction(self, currentRequest, macroItems):
        request_info = self.helpers.analyzeRequest(currentRequest)
        #Extract the Bearer token from the macro response
        macro_response_info = self.helpers.analyzeResponse(macroItems[0].getResponse())
       
        macro_msg = macroItems[0].getResponse()   
        resp_body = macro_msg[macro_response_info.getBodyOffset():]
        macro_body_string = self.helpers.bytesToString(resp_body)
        bearer_token = json.loads(macro_body_string)

        '''
            These are a bunch of the lines I added for debugging and locating
            the target parameter within a JSON response body.
            bearer_token, defined above, contains the JSON response body.
        '''
        # self.stdout.println("printing macro_body_string: " + macro_body_string)
        # self.stdout.println("printing  to json: dict print by self on next line:")
        # self.stdout.println(bearer_token)
        # self.stdout.println("breaking down elements:")
        # self.stdout.println("JSON parent section:")
        # self.stdout.println(bearer_token["JSON_parent"])
        # self.stdout.println("JSON_child section:")
        # self.stdout.println(bearer_token["JSON_parent"]["JSON_child"])
        # self.stdout.println("JSON_child_2 section:")
        # self.stdout.println(bearer_token["JSON_parent"]["JSON_child"]["JSON_child_2"])
     
        '''
            This next section can be modified/duplicated as needed to store 
            multiple params from a JSON response body in various variables.
            bearer_token, defined above, contains the JSON response body.
            The resulting macro_body_param variable may be added to the 
            outgoing request body or headers as needed later on.
        '''        
        macro_body_param = bearer_token["JSON_parent"]["JSON_child"]
        self.stdout.println("Retrieved macro_body_param value:")
        self.stdout.println(macro_body_param)
        self.stdout.println("\n")    

        '''
            The original script stores the next request's headers and body 
            in variables for modification prior to sending.
        '''
        headers = request_info.getHeaders()
        req_body = currentRequest.getRequest()[request_info.getBodyOffset():]

        '''
            This section is used when outgoing request bodies aren't in JSON format.
            There is some unnecessary type conversion going on here, and that's just 
            how it happened in the heat of an engagement hacking rapidly at this script.

            The request body is manipulated as big string variable after being converted from 
            bytes, and regex is used to find the insertion point of the parameter pulled from 
            the macro response body above, and to replace it.
        '''
        # This is a lot of my work ripping the request byte object apart and putting it back together. 
        # I later found an easier way to get the string: PyArray.tostring() method.
        self.stdout.println("This is the final type I need to get the re-assembled request back into:")
        self.stdout.println(type(req_body))
        ## 3/2022 I could probably have just kept everything as bytes instead of converting 
        # to strings and back. The python re module seems to accept bytes in the format: b'a string'
        #   https://stackoverflow.com/questions/44457455/python3-regex-on-bytes-variable      
        self.stdout.println("This is the req_body typecasted to a bytearray:")
        self.stdout.println(bytearray(req_body))
        req_body_byar = bytearray(req_body)
        self.stdout.println("Printing again after trying to get a string representation")
        ### I can just use the PyArray.tostring() here next time.
        req_body_str = str(req_body_byar)
        self.stdout.println(req_body_str)

        ### In this block, regex search the request body string for the token, 
        # and add it to a named regex group, "token".
        match_string = 'Token[\":\s]+(?P<token>[0-9a-f]+)\"'
        self.stdout.println("Printing matching pattern to be used:")
        self.stdout.println(match_string)
        search = re.search(match_string, req_body_str)
        self.stdout.println("Printing matches within match object:")
        self.stdout.println(search)
        self.stdout.println(search.group(0))
        self.stdout.println(search.group(1))
        self.stdout.println(search.group('token'))
        ### Using match indexes, pull the request body string apart before and after the match.
        self.stdout.println("[*] Starting to work with Substrings here.")
        start = search.start('token')
        end = search.end('token')
        self.stdout.println(start)
        self.stdout.println(end)
        ### Reassamble the body using the indexes
        new_body_str_start = req_body_str[:start]
        self.stdout.println(new_body_str_start)
        self.stdout.println(macro_body_param)
        new_body_str_end = req_body_str[end:]
        self.stdout.println(new_body_str_end)
        ### Assemble the new request body and convert to bytes for request transmission
        new_body_str = new_body_str_start + macro_body_param + new_body_str_end
        new_body_bytes = bytearray(new_body_str.encode('ascii'))

        '''
            Most of this is the original code from the copied extension
            with some debugging println lines that I added.
        '''
        resp_headers = macro_response_info.getHeaders() 
        headers = request_info.getHeaders()
        self.stdout.println("Going to print all the response headers")
        self.stdout.println(type(resp_headers))
        macro_header = ''
        for item in resp_headers:
            if 'header_to_copy:' in item:
                macro_header = item
        self.stdout.println("Printing target header after extraction from response")
        self.stdout.println(macro_header)
    
        '''
            This next section loops through the outbound request headers several times
            removing a named header each time or simply passing if not found.
            The original extension had one header loop, and I duplicated as needed.
        '''
        auth_header_to_delete = ''
        for head in headers:
            if 'Authorization: Bearer ' in head:
                auth_header_to_delete = head      
        try:
            headers.remove(auth_header_to_delete)
        except:
            pass
        auth_header_to_delete = ''
        for head in headers:
            if 'named_header_to_delete' in head:
                auth_header_to_delete = head         
        try:
            headers.remove(auth_header_to_delete)
        except:
            pass
        auth_header_to_delete = ''
        for head in headers:
            if 'another_named_header_to_delete:' in head:
                auth_header_to_delete = head         
        try:
            headers.remove(auth_header_to_delete)
        except:
            pass

        '''
            Finally, these last two blocks add headers as needed and combine with 
            the modified request body for sending to the application.
            Comment or uncomment to add/remove functionality as needed.

            Headers being added here are variables from above that came from either the 
            macro response body or macro response headers.
        '''
        headers.add('Authorization: Bearer ' + macro_body_param)       
        headers.add('named_header_to_add: ' + macro_header)  
        #headers.add('another_named_header_to_add' + macro_header_2)  
        self.stdout.println('Header Checked at time :  {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))               
        self.stdout.println("-----------------------------------------------------------------\n\n")               

        '''
            When building the message variable to send as the outgoing request, 
            headers is the modified headers object with replaced headers.
            req_body can be used when the body did not require modification prior to sending,
            and new_body_bytes is used when the body was modified by this extension.
        '''   
        #message = self.helpers.buildHttpMessage(headers, req_body)      
        message = self.helpers.buildHttpMessage(headers, new_body_bytes)  
        self.stdout.println("[*] Printing final message w updated body:") 
        self.stdout.println(message.tostring())
        # Send it:    
        currentRequest.setRequest(message)
        return
        FixBurpExceptions()
