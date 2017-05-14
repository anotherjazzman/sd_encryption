//package SD_Security;
import java.io.*;
import java.io.IOException;
import java.lang.*;
import java.util.*;
import java.util.zip.*;
import javax.swing.*;
import com.hp.itsm.api.*;
import com.hp.itsm.api.interfaces.*;
import com.hp.ifc.util.ApiDateUtils;


class SD_Form {
 
//  Atttributes
    
    public String sd_encrypt_fields = null;
    public String sd_description = null;
    public Long sd_id;
    public String information = null;
    public String solution = null;
    public IChange encrypt_record = null;
    public String sd_status = null;
    public String sd_project = null;
    public String sd_manager = null;
    public String sd_classification = null;
    public String sd_workaround = null;
    public String sd_ci = null;
    public String userDisplayName = null;
    public IPerson[] users_ci;
    public String form_signers = null;
    
 /************************************************************************************/
 /* get_SD_Fields() - This function gets security software configuration information */
 /*                    and change record information from the SD database to be used */
 /*                    later in the other functions.                                 */
 /************************************************************************************/   
       
    public int get_SD_Fields(SD_Global variables, SD_Common function, SD_Security_System sd_security,String security_name, String[] server, Long id,int flag) {
  
 /* Service Desk login information */
       
        int num_servers = 0;
        String appl_server = server[num_servers];
        ++num_servers;
        variables.debugFlag = flag;
        
        int tries = 1;
        
// Allow three attempts to enter Service Desk Login name and Password
        int no_prompt = 0;
       while (tries < 4)
       { 
         if (no_prompt != 1)
          {
           function.prompt_user_info(variables,"Enter SD Login Name: ");
          }
       
/* Assign incoming Service Desk change request ID */
        
        sd_id = id;
        
        /*	Open a session to a running Service Desk application Server.
         *	Once you have a connection, you can use it to communicate with
         *	the server. The connection is to an instance of the workflow layer
         *	in the server that keeps state information for this client.
         */
        try {
            variables.session = ApiSDSession.openSession(appl_server, variables.username, variables.password);

// If session is null then try again otherwise continue with getting fields.
            
            if (variables.session == null)
            {
                ++tries;
            }
            else 
            {
               tries = 4;
            }
        } catch (RuntimeException e) {
            /*	Connecting can go wrong for various reasons. E.G. No server is
             *	running on this particular computer/port combination
             *	or the user/password combination was wrong. Catch the exception and
             *	print an error message for the user or for the log. The Web-API makes
             *	an effort to give sensible messages in the exceptions that it throws,
             *	and if possible, the messages are localised.
             *
             *	NOTE that using System.out.println() can be problematic in some
             *	applications.
            */
 
// If login fails three times then print error and exit.
            
              if (tries == 3)
              {
                  function.display_message ("Error in get_SD_fields(): 3 attempts to login to Service Desk have failed");
                  return 1;
              }
//              function.display_message ("In get_SD_fields(): trying host...");
              if (e.getMessage().indexOf("Unable to connect to host") < 0)
              {
                function.display_message ("Error in get_SD_fields(): "+e.getMessage());
                no_prompt = 0;
                ++tries;
              }
             else
              {
                  if (server[num_servers].compareTo("NO_MORE") != 0)
                  {
                      function.display_message("Host: "+server[num_servers-1]);
                      appl_server = server[num_servers];
                      function.display_message("Host: "+server[num_servers]);
                      ++num_servers;
                      no_prompt = 1;
                  }
                  else
                  {
                    function.display_message ("Error in get_SD_fields(): Unable to connect to an application server");
                    return 1; 
                  }
              }
        }
    }
        // Get the account using this session.
        // This illustrates how to retrieve a related or aggregated object.
 //               function.display_message ("In get_SD_fields(): getCurrentAccount...");     
        try 
        {
          IAccount account = variables.session.getCurrentAccount();
          
           if (account == null)
            {
              function.display_message ("Error in get_SD_fields(): Unable to get account information");
              return 1;
            }
   
 // Get SD person record for this account.
          
           IPerson[] persons = account.getPerson_Account();
        
           if (persons.length == 0)
            {
             function.display_message ("Error in get_SD_fields(): No Person record associated with account "+account.getDisplayName());
             return 1;
            }

 // Get SD Encryption field which determines "signer" or "viewer"
          IPersonCode2 pcode2 = persons[0].getPersonCode2();
          if (pcode2 == null)
          {
               function.display_message ("Error in get_SD_fields(): Unable to determine SD Encryption Role (Signer or Viewer)");
          }        
           String pcode_text = pcode2.getText();

// Determine if the person is a "signer" or "viewer"
           
           if (pcode_text.compareTo("Signer") == 0)
           {
               variables.signer_or_viewer = 1;
          }
           
      // What is the display name of this account?
      // This illustrates how to retrieve properties of an object.
        
        userDisplayName = account.getDisplayName();
//                     function.display_message ("In get_SD_fields(): getDisplayName()..."); 
           
// Determine if the account is an allowed user of the SD Encryption CI.
           
         IConfigurationItem[] cis = persons[0].getUserOfCI();
//                       function.display_message ("In get_SD_fields(): getUserOfCI()...");
        if (cis.length == 0)
        {
          function.display_message ("Error in get_SD_fields(): Account "+userDisplayName+" is not a user of any CIs! ");
//           function.display_message ("In get_SD_fields(): cis_length is zero...");
          return 1;
        }
// function.display_message ("In get_SD_fields(): getPersonOrganization()...");
// Get SD organization
         
         String organization = persons[0].getPersonOrganization().getSearchcode();
//         function.display_message ("In get_SD_fields(): getPersonOrganization()...");
         if (organization == null)
         {
             function.display_message ("Error in get_SD_fields(): Person does not belong to an organization");
             return 1;
         }
         

// Combination of SD Encryption name and organization is SD CI name
         
         String security_ci = security_name+organization;
         sd_security.Name = security_name;
        
        
// Search for configuration information for Encryption Software
        
        int found_ci = 0;
        
        for (int j = 0; j < cis.length; j++) {
            
            String searchCode = cis[j].getSearchcode();
// Once found, get configuration information for Encryption software and 
// Service Desk fields to be used in encryption and decryption of form
            
            if (searchCode.compareTo(security_ci) == 0) {
                variables.command_info = cis[j].getName1();
                sd_encrypt_fields = cis[j].getName2();
                users_ci = cis[j].getUsers();
                j = cis.length;
                found_ci = 1;
            }
        }
 
 // If Encryption system CI not found then print error and return.
 //       function.display_message ("In get_SD_fields(): found_ci...");
         if (found_ci == 0)
         {
            function.display_message ("Error in get_SD_fields(): Account "+userDisplayName+" not authorized user of "+security_name);
            return 1;
         }
        }  catch (RuntimeException e) {
            function.display_message ("Error in get_SD_fields(): "+e.getMessage());
            return 1;
        }
        
 // Determine if Cipher Text software configuration is defined.
//       function.display_message ("In get_SD_fields(): sd_encrypt_fields...");
        if (sd_encrypt_fields == null)
        {
             function.display_message ("Error in get_SD_fields(): Change record fields to be signed/compared/displayed not defined");
            return 1;
        }
        
// Determine if fields to be signed for change record is defined.
//       function.display_message ("In get_SD_fields(): variables.command_info...");
        if (variables.command_info == null)
        {
            function.display_message ("Error in get_SD_fields(): Cipher Text Software configuration not defined");
            return 1;
        }
// Parse through Encryption software configuration information and assign to
// class attributes.
       try { 
 // Setup list of security software configuration information
        int equal_pos;
        StringTokenizer fields = new StringTokenizer(variables.command_info,variables.config_field_separator);
        
        String variable_name = null;
        String command_name = null;

// Parse out Encryption system information.
        
        while (fields.hasMoreTokens()) {
            command_name = fields.nextToken();
            
            if (command_name.length() == 0)
            {
                continue;
            }
// Search for equal sign which is dividing point between variable and value.
            
            equal_pos = command_name.indexOf("=");
            variable_name = command_name.substring(0,equal_pos);
            variable_name.trim();
            ++equal_pos;
            
// Assign app_path variable
            
            if (variable_name.indexOf("a_path") > 0){
                sd_security.app_path = command_name.substring(equal_pos);
                continue;
            }

// Assign global variable logfile directory
            
           if (variable_name.indexOf("l_file") > 0){
                variables.log_file = command_name.substring(equal_pos);
                
                 if (variables.debugFlag == 1)
                  {
                    try {
                        variables.log_file = variables.log_file+"."+id.toString();
                        variables.logfile = new BufferedWriter(new FileWriter(variables.log_file));
                    } catch (IOException e) {
                      function.display_message ("Error in creating log_file "+variables.log_file+" :"+e.getMessage());
                    }
                 }
                
                continue;
            }
// Assign global temp_path directory
            
            if (variable_name.indexOf("t_path") > 0){
                variables.temp_path = command_name.substring(equal_pos);
                continue;
            }
            
// Assign global sign_file variable
            
            if (variable_name.indexOf("s_file") > 0){
                variables.sign_file = command_name.substring(equal_pos);
                continue;
            }
// Assign file_extension variable
            
            if (variable_name.indexOf("f_ext") > 0){
                sd_security.file_ext = command_name.substring(equal_pos);
                continue;
            }
// Assign encrypt_command variable
            if (variable_name.indexOf("en_cmd") > 0){
                sd_security.encrypt_command = command_name.substring(equal_pos);
                continue;
            }

// Assign decrypt command variable
           
            if (variable_name.indexOf("dec_cmd") > 0){
                sd_security.decrypt_command = command_name.substring(equal_pos);
                continue;
            }

// Assign verify_command variable
            if (variable_name.indexOf("v_cmd") > 0){
                sd_security.verify_command = command_name.substring(equal_pos);
                continue;
            }
            
// Assign display_command variable
            if (variable_name.indexOf("dis_cmd") > 0){
                sd_security.display_command = command_name.substring(equal_pos);
                continue;
            }
            
// Assign authorize_command variable          
            if (variable_name.indexOf("a_cmd") > 0){
                sd_security.authorize_command = command_name.substring(equal_pos);
                continue;
            }
        }
       }
       catch (RuntimeException e) {
           function.display_message ("Error in get_SD_fields(): "+e.getMessage());
           return 1;
       }
        
// Get Change Management record home to search for change management record
        IChangeHome changeHome = variables.session.getChangeHome();
        
        if (changeHome == null) {
            function.display_message("Error in get_SD_fields(): failure in getChangeHome()");
            return 1;
        }
        IChange[] chg_record = null;
        chg_record = changeHome.findAllChange();
        
         if (chg_record.length == 0) {
            function.display_message("Error in get_SD_fields(): failure in findAllChange()");
            return 1;
        }
// Find change management record and get possible information that can be used to 
// sign form.
        
         int found_chg = 0;
         String runtime_exceptions = "";
         
        for (int a = 0; a < chg_record.length; ++a) {
            if (sd_id.compareTo(chg_record[a].getID())== 0) {
                found_chg = 1;
             try{
                 solution = chg_record[a].getSolution();
              }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     solution = null;
                }
                
              try {
               information = chg_record[a].getInformation();
              }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     information = null;
                }
                
               try {
               sd_description = chg_record[a].getDescription();
              }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     sd_description = null;
                }
                
               try {
               sd_status = chg_record[a].getStatus().getText();
              }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     sd_status = null;
                }
                
                 try {
                      sd_project = chg_record[a].getProject().getDescription();
              }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     sd_project = null;
                }
               
                 try {
                      sd_manager = chg_record[a].getManager().getName();
              }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     sd_manager = null;
                }
                
                try {
                      sd_classification = chg_record[a].getClassification().getText();
                }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     sd_classification = null;
                }
               
                try {
                     sd_workaround = chg_record[a].getWorkaround(); 
                }
                catch (RuntimeException e) {
            //	Database error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     sd_workaround = null;
                }
                try {
                    
                   sd_ci = chg_record[a].getConfigurationItem().getName1();
                }
                catch (RuntimeException e) {
                    runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                    sd_ci = null;
                }
// Assign change record to variable so it can be referenced at a later time.
                
                encrypt_record = chg_record[a];
                
// Exit out of loop.
                
                a = chg_record.length;
            }
        }
// Determine if the change record was found. If not print error and return.
         
         if (found_chg == 0)
         {
             function.display_message ("Error in get_SD_fields(): Unable to find record "+sd_id.toString());
             return 1;
         }
         
// Get list of people who have already signed the form.
         
        String enc = encrypt_record.getChangeText64kB();
        
        if ( enc != null)
        {
        StringTokenizer fields = new StringTokenizer (enc, variables.stars);
   
   // First field is always list of signers information.
            
         form_signers = fields.nextToken();
    
        }
// If flag set then write exceptions to logfile.
         
         if (variables.debugFlag == 1)
         {
             try {
              variables.logfile.write(runtime_exceptions);
             } catch (IOException e) {
                 function.display_message ("Error in writing to logfile "+variables.log_file+" : "+e.getMessage());
             }
         }
        return 0;
    }
 /**********************************************************************************/
/* is_form_approved() - This function determines if a form is approved based on    */
/*                    information on the approval sheet.                           */
/************************************************************************************/   
    public int is_form_approved(SD_Common function)
    {
      try {
//      String approval_result = encrypt_record.getApproval().getApprovalResult();
      
       if (sd_status.compareTo("Approved") != 0)
//       if (approval_result.compareTo("Approved") != 0)
        {
            return 1;
        }
        return 0;
    } catch (RuntimeException e) {
        function.display_message ("Error in is_form_approved: "+e.getMessage());
        return 1;
    }
  }

}     
       
 