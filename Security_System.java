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

class Security_System {
 
// Definition of attributes
    
    public String Name;
    public String app_path;
    public String temp_path;
    public String sign_file;
    public String encrypt_command;
    public String decrypt_command;
    public String verify_command;
    public String display_command;
    public String authorize_command;
    public String file_ext;
    
// Initialization of Global variables
    
    ApiSDSession session = null;
    String sd_encrypt_fields = null;
    String sd_description = null;
    Long sd_id;
    String information = null;
    String solution = null;
    IChange encrypt_record = null;
    String sd_status = null;
    String sd_project = null;
    String sd_manager = null;
    String sd_classification = null;
    String sd_workaround = null;
    String sd_ci = null;
    String userDisplayName = null;
    String command_info = null;
    String entry_separator = ";;";
    String field_separator = "::";
    String config_field_separator = ";";
    String username = null;
    String password = null;
    String output_line = null;
    int debugFlag = 0;
    String log_file = null;
    BufferedWriter logfile;
    IPerson[] users_ci;
    String decrypted_field = null;
    int no_sigs = 0;
    String stars = "******************************************************";
    int signer_or_viewer = 0;
    String form_signers = null;
 /************************************************************************************/
 /* get_SD_Fields() - This function gets security software configuration information */
 /*                    and change record information from the SD database to be used */
 /*                    later in the other functions.                                 */
 /************************************************************************************/   
       
    public int get_SD_Fields(String security_name,Long id,int flag) {
  
 /* Service Desk login information */
        
        String server = "intrepid";
        
        debugFlag = flag;
        
        int tries = 1;
        
// Allow three attempts to enter Service Desk Login name and Password
        
       while (tries < 4)
       {
          prompt_user_info("Enter SD Login Name: ");
        
/* Assign incoming Service Desk change request ID */
        
        sd_id = id;
        
        /*	Open a session to a running Service Desk application Server.
         *	Once you have a connection, you can use it to communicate with
         *	the server. The connection is to an instance of the workflow layer
         *	in the server that keeps state information for this client.
         */
        try {
            session = ApiSDSession.openSession(server, username, password);

// If session is null then try again otherwise continue with getting fields.
            
            if (session == null)
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
                  display_message ("Error in get_SD_fields(): 3 attempts to login to Service Desk have failed");
                  return 1;
              }
              
              display_message ("Error in get_SD_fields(): "+e.getMessage());
              ++tries;
        }
    }
        // Get the account using this session.
        // This illustrates how to retrieve a related or aggregated object.
       
        try 
        {
          IAccount account = session.getCurrentAccount();
          
           if (account == null)
            {
              display_message ("Error in get_SD_fields(): Unable to get account information");
              return 1;
            }
   
 // Get SD person record for this account.
          
           IPerson[] persons = account.getPerson_Account();
        
           if (persons.length == 0)
            {
             display_message ("Error in get_SD_fields(): No Person record associated with account "+account.getDisplayName());
             return 1;
            }

           IPersonCode2 pcode2 = persons[0].getPersonCode2();
           
           if (pcode2 == null)
           {
               display_message ("Unable to get person code");
           }
           
           String pcode_text = pcode2.getText();
           
           if (pcode_text.compareTo("Signer") == 0)
           {
               signer_or_viewer = 1;
           }
           
           
// Determine if the account is an allowed user of the Security System CI.
           
         IConfigurationItem[] cis = persons[0].getUserOfCI();
         
         String organization = persons[0].getPersonOrganization().getSearchcode();
         
         if (organization == null)
         {
             display_message ("Person does not belong to an organization");
             return 1;
         }
         
        
         String security_ci = security_name+organization;
        
        if (cis.length == 0)
        {
            display_message ("Error in get_SD_fields(): Account "+account.getDisplayName()+" not authorized user of "+security_name);
            return 1;
        }
        
        // What is the display name of this account?
        // This illustrates how to retrieve properties of an object.
        
        userDisplayName = account.getDisplayName();
        
        
// Search for configuration information for Security software
        
        int found_ci = 0;
        
        for (int j = 0; j < cis.length; j++) {
            
            String searchCode = cis[j].getSearchcode();

// Once found, get configuration information for Security software and 
// Service Desk fields to be used in encryption and decryption of form
            
            if (searchCode.compareTo(security_ci) == 0) {
                command_info = cis[j].getName1();
                sd_encrypt_fields = cis[j].getName2();
                users_ci = cis[j].getUsers();
                j = cis.length;
                found_ci = 1;
            }
        }
 
 // If security system CI not found then print error and return.
        
         if (found_ci == 0)
         {
            display_message ("Error in get_SD_fields(): Account "+userDisplayName+" not authorized user of "+security_name);
            return 1;
         }
        }  catch (RuntimeException e) {
            display_message ("Error in get_SD_fields(): "+e.getMessage());
            return 1;
        }
        
// Parse through security software configuration information and assign to
// class attributes.
       try { 
 // Setup list of security software configuration information
        int equal_pos;
        StringTokenizer fields = new StringTokenizer(command_info,config_field_separator);
        
        String variable_name = null;
        String command_name = null;

// Parse out security system information.
        
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
                app_path = command_name.substring(equal_pos);
                continue;
            }
            
           if (variable_name.indexOf("l_file") > 0){
                log_file = command_name.substring(equal_pos);
                
                 if (debugFlag == 1)
                  {
                    try {
                        log_file = log_file+"."+id.toString();
                        logfile = new BufferedWriter(new FileWriter(log_file));
                    } catch (IOException e) {
                      display_message ("Error in creating log_file "+log_file+" :"+e.getMessage());
                    }
                 }
                
                continue;
            }
// Assign temp_path variable
            
            if (variable_name.indexOf("t_path") > 0){
                temp_path = command_name.substring(equal_pos);
                continue;
            }
            
// Assign sign_file variable
            
            if (variable_name.indexOf("s_file") > 0){
                sign_file = command_name.substring(equal_pos);
                continue;
            }
// Assign file_extension variable
            
            if (variable_name.indexOf("f_ext") > 0){
                file_ext = command_name.substring(equal_pos);
                continue;
            }
// Assign encrypt_command variable
            if (variable_name.indexOf("e_cmd") > 0){
                encrypt_command = command_name.substring(equal_pos);
                continue;
            }

// Assign decrypt command variable
           
            if (variable_name.indexOf("dec_cmd") > 0){
                decrypt_command = command_name.substring(equal_pos);
                continue;
            }

// Assign verify_command variable
            if (variable_name.indexOf("v_cmd") > 0){
                verify_command = command_name.substring(equal_pos);
                continue;
            }
            
            // Assign verify_command variable
            if (variable_name.indexOf("dis_cmd") > 0){
                display_command = command_name.substring(equal_pos);
                continue;
            }
            
// Assign authorize_command variable          
            if (variable_name.indexOf("a_cmd") > 0){
                authorize_command = command_name.substring(equal_pos);
                continue;
            }
        }
       }
       catch (RuntimeException e) {
           display_message ("Error in get_SD_fields(): "+e.getMessage());
           return 1;
       }
        
// Get Change Management record home to search for change management record
        IChangeHome changeHome = session.getChangeHome();
        
        if (changeHome == null) {
            display_message("Error in get_SD_fields(): failure in getChangeHome()");
            return 1;
        }
        IChange[] chg_record = null;
        chg_record = changeHome.findAllChange();
        
         if (chg_record.length == 0) {
            display_message("Error in get_SD_fields(): failure in findAllChange()");
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
            //	Datbase error or field is not populated
            //	Give message and set field to null
                     runtime_exceptions = runtime_exceptions +"Warning in get_SD_fields(): "+e.getMessage()+"\n";
                     solution = null;
                }
                
              try {
               information = chg_record[a].getInformation();
              }
                catch (RuntimeException e) {
            //	Datbase error or field is not populated
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
            //	Datbase error or field is not populated
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
// Assign change record to global variable so it can be referenced at a later time.
                
                encrypt_record = chg_record[a];
                
// Exit out of loop.
                
                a = chg_record.length;
            }
        }
// Determine if the change record was found. If not print error and return.
         
         if (found_chg == 0)
         {
             display_message ("Error in get_SD_fields(): Unable to find record "+sd_id.toString());
             return 1;
         }
         
         form_signers = encrypt_record.getChangeText2();
         
         if (debugFlag == 1)
         {
             try {
              logfile.write(runtime_exceptions);
             } catch (IOException e) {
                 display_message ("Error in writing to logfile "+log_file+" : "+e.getMessage());
             }
         }
        return 0;
    }
 /***********************************************************************************/
 /* Authorize_user() - This function determines if the user has a security key to   */
 /*                    and whether the user is allowed to use the security software */
 /***********************************************************************************/   
    
    public int authorizes_user() {
        
 // Create name of Security user keyfile with the ID of change record
        
        String keyfile = temp_path+sd_id.toString()+"keyfile";

// Setup Security System authorize command.
        
        String command = authorize_command+" ";
        
// Create name of batch file to execute Security authorize command with ID of change record
        
        String batch_file = temp_path+sd_id.toString()+"getKey.bat";
        
// Write commands into the batch file.
        
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(command);
            bat_file.write((int) '"');
            
            for (int z = 0; z < userDisplayName.length(); ++z) {
                bat_file.write((int) userDisplayName.charAt(z));
            }
            bat_file.write((int) '"');
            bat_file.write(" ");
            bat_file.write(keyfile);
            
            /*  bat_file.write(command);*/
            bat_file.close();
        } catch (IOException e) {
            display_message ("Error in authorize_user(): "+e.getMessage());
        }
   
// Setup to delete the key file. The batch file will be deleted in the execute_bat function
        
        File del_key = new File(keyfile);
  
// Execute the batch file and check to see if the user has a public/private key.
        
        if (execute_bat(batch_file, keyfile,0) == 0) {
 
// Delete the keyfile.
            
            try {
                del_key.delete();
            }
            catch (SecurityException e) {
                display_message("Error in authorizes_user(): file "+del_key.toString()+" "+e.getMessage());
            }
            return 0;
        }
        else {
            
// Delete the keyfile.
            
            try {
                del_key.delete();
            }
            catch (SecurityException e) {
                display_message("Error in authorizes_user(): file "+del_key.toString()+" "+e.getMessage());
            }
            display_message("Error in authorizes_user(): User information not defined in security software");
            return 1;
        }
    }
    
/************************************************************************************/
 /* create_signature() - This function creates an digital signature based on        */
 /*                    various fields on the SD change record.                      */
 /************************************************************************************/   
           
public int create_signature() {
    
    if (signer_or_viewer == 0)
    {
        display_message ("Warning: "+userDisplayName+" is not an authorized signer");
        return 0;
    }
   
    if (form_signers != null)
    {
        if (form_signers.indexOf(userDisplayName) > -1)
        {
          display_message ("Warning: "+userDisplayName+" has already signed form");
          return 0;
        }
    }
    
// Setup array to contain the list of SD fields that should be in the digital signature.
    
        StringTokenizer fields = new StringTokenizer(sd_encrypt_fields,config_field_separator);
 
// Temporary field to hold SD fields from the Configuration Item form.
        
        String sd_field = null;
  
// String to hold the fields and values from the SD form.
        
        String encryption_string = null+entry_separator;
        String null_fields = " ";

// Determine if the form is alread signed. If already sign allow user to re-create
// signature or exit with creating new signature.
        
        String record = encrypt_record.getChangeText64kB();
     try {
        if (record != null)
        {
                decrypts_data ("add_signer");
                return 0;
        }
     }catch (RuntimeException e) {
                    display_message ("Error in Create_Signature for getChangeText64KB: "+e.getMessage());
                    return 0;
      }
       
// Cycle through list of SD fields from Configuration Item form and and field name and
// value to the encryption_string. In addition, keep track of those fields that do not
// have values.
        
        encryption_string = userDisplayName+entry_separator;
        
        while (fields.hasMoreTokens()) {
            sd_field = fields.nextToken();
            
            if (sd_field.compareTo("ID") == 0) {
                encryption_string = encryption_string+"ID"+field_separator+sd_id.toString()+entry_separator;
            }
            
            if (sd_field.compareTo("Description") == 0) {
                
                if (sd_description == null)
                {
                    null_fields = null_fields+"\n"+"Description";
                }
                encryption_string = encryption_string+"Description"+field_separator+sd_description+entry_separator;
            }
            
            if (sd_field.compareTo("Information") == 0) {
                
                if (information == null)
                {
                    null_fields = null_fields+"\n"+"Information";
                }
                 
                encryption_string = encryption_string+"Information"+field_separator+information+entry_separator;
            }
            if (sd_field.compareTo("Project") == 0) {
                
                if (sd_project == null)
                {
                    null_fields = null_fields+"\n"+"Project";
                }
                
                encryption_string = encryption_string+"Project"+field_separator+sd_project+entry_separator;
            }
            
            if (sd_field.compareTo("Status") == 0) {
                
                if (sd_status == null)
                {
                    null_fields = null_fields+"\n"+"Status";
                }
                
                encryption_string = encryption_string+"Status"+field_separator+sd_status+entry_separator;
            }
            
            if (sd_field.compareTo("Classification") == 0) {
                
                if (sd_classification == null)
                {
                    null_fields = null_fields+"\n"+"Classification";
                }
                
                encryption_string = encryption_string+"Classification"+field_separator+sd_classification+entry_separator;
            }
            
            if (sd_field.compareTo("Solution") == 0) {
                
                if (solution == null)
                {
                    null_fields = null_fields+"\n"+"Solution";
                }
                
                encryption_string = encryption_string+"Solution"+field_separator+solution+entry_separator;
            }
            
            if (sd_field.compareTo("Manager") == 0) {
                
                if (sd_manager == null)
                {
                    null_fields = null_fields+"\n"+"Manager";
                }
                
                encryption_string = encryption_string+"Manager"+field_separator+sd_manager+entry_separator;
            }
            
             if (sd_field.compareTo("Workaround") == 0) {
                 
                if (sd_workaround == null)
                {
                    null_fields = null_fields+"\n"+"Workaround";
                }
                encryption_string = encryption_string+"Workaround"+field_separator+sd_workaround+entry_separator;
            }
            
             if (sd_field.compareTo("CI") == 0) {
                 
                if (sd_ci == null)
                {
                    null_fields = null_fields+"\n"+"CI";
                }
                encryption_string = encryption_string+"CI"+field_separator+sd_ci+entry_separator;
            }
        }
        
// If there were fields that have null value, allow user to either continue with creating
// signature or aborting.
        
        if (null_fields.length() > 1)
        {
            if (prompt_user ("The following fields below contain no information:\n"+null_fields+"\n\n"+"Do you still want to sign the form?\n") != 0)
            {
                return 1;
            }
        }
        
          if (debugFlag == 1)
           {
             try {
              logfile.write("Encryption string = "+encryption_string);
             } catch (IOException e) {
                 display_message ("Error in writing to logfile "+log_file+" : "+e.getMessage());
             }
         }
        
// Create name of the file that will hold the encryption string to be encrypted
// by the security software.
        
        String sig_file = temp_path+sd_id.toString()+".sig.asc";
        String file_name = temp_path+sd_id.toString();
        
// Write encryption string into file.
        
        try {
            BufferedWriter file_to_encrypt = new BufferedWriter(new FileWriter(file_name));
            file_to_encrypt.write(encryption_string);
            file_to_encrypt.close();
        }
        catch (IOException e) {
            display_message("Error in create_signature() for file : "+file_name+e.getMessage());
        }
   
        String pgp_password = prompt_password ("PGP Password");
        
        if (pgp_password == null)
        {
            display_message ("Error in create_signature(): PGP password was not entered correctly");
        }
        
// Setup encrypt and sign command.
        
        String command1 = sign_file+" ";
        String command = encrypt_command+" ";
        
// Setup batch file name to execute encrypt and sign command.
        
        String batch_file = file_name+"encrypt"+".bat";
        
// Write encrypt and sign commands into the batch file.
        
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(command1);
            bat_file.write(" -o ");
            bat_file.write(sig_file);
            bat_file.write(" ");
            bat_file.write(file_name);
            bat_file.write(" -u ");
            bat_file.write((int) '"');
            
            for (int v = 0; v < userDisplayName.length(); ++v) {
               bat_file.write((int) userDisplayName.charAt(v));
            }   
            bat_file.write((int) '"');
            bat_file.write (" -z "+pgp_password);
            bat_file.write ("\n");
            
            bat_file.write(command);
            bat_file.write(" ");
            bat_file.write(file_name);
            bat_file.write(" ");
            
            String rep;
            for (int y = 0; y < users_ci.length; ++y)
            {
                rep = users_ci[y].getAccount().getDisplayName();
                
                bat_file.write((int) '"');
            
               for (int z = 0; z < rep.length(); ++z) {
                bat_file.write((int) rep.charAt(z));
               }
                 bat_file.write((int) '"');
                 bat_file.write(" ");
            }
            
            bat_file.write (" -z "+pgp_password);
            
            bat_file.close();
        } catch (IOException e) {
            display_message("Error in create_signature(): file "+batch_file+" "+e.getMessage());
        }
        
// Setup name of resulting file from encrypt and sign command.
        
        String encrypt_file = file_name+file_ext;

// Setup files for deletion. batch file will be deleted by execute_bat function.
        
        File del_filename = new File(file_name);
        File del_encrypt = new File(encrypt_file);

// Execute encrypt and sign command and check for resulting file.
        
        if (execute_bat(batch_file, encrypt_file,0) == 0) {
            put_signature (file_name,encrypt_file,sig_file);
            display_message ("Signature for "+userDisplayName+" successfully added to record");
            return 0;
        }
        else {
            display_message ("Error in create_signature(): Unable to encrypt fields");

// Delete file            
            try {
                del_encrypt.delete();
            }
            catch (SecurityException e) {
                display_message("Error in create_signature(): file "+del_encrypt.toString()+" "+e.getMessage());
            }
            return 1;
        }
    }

/************************************************************************************/
 /* put_signature() - This function attaches the digital signature to the change    */
 /*                   record.                                                      */
 /************************************************************************************/   
       
    public int put_signature (String file_name, String encrypt_file, String sig_file)
    {
        
// Setup file for deletion.
        
        File del_filename = new File(file_name);
        File del_encrypt = new File(encrypt_file);

// Read-in encrypted information to be placed in the SD form.
        
           try {
                
                File f = new File(encrypt_file);
                
                int length = (int) f.length();
                
                FileInputStream fis = new FileInputStream(f);
                
                byte[] buffer = new byte[length];
                
                fis.read(buffer);    
                
                fis.close();
                
                
                File s = new File(sig_file);
                
                length = (int) s.length();
                
                FileInputStream fiss = new FileInputStream(s);
                
                byte[] buffer2 = new byte[length];
                
                fiss.read(buffer2);    
                
                fiss.close();
                // the whole file is read into buffer
                
                StringBuffer sb = new StringBuffer(new String(buffer));
                StringBuffer sb1 = new StringBuffer(new String(buffer2));
                
// Convert encryption information into a String to be stored with SD form.
                
                String fields_out = sb.toString();
                String sig_out = sb1.toString();
                
                String out_line = fields_out+"\n"+stars+sig_out+"\n"+stars;

// Save the encryption information with SD form.
                
                encrypt_record.setChangeText64kB(out_line);
                
// Ensure that you can get the encrypted information.
                
                String record_signature = encrypt_record.getChangeText64kB();
 
                  if (debugFlag == 1)
                  {
                   try {
                        logfile.write("encrypt data = "+record_signature);
                        logfile.write ("Length of signature file = "+out_line.length());
                        logfile.write ("Length of signature attached to record = "+record_signature.length());
                   } catch (IOException e) {
                     display_message ("Error in writing to logfile "+log_file+" : "+e.getMessage());
                   }
                 }
                
// Ensure that the length of the encryption information stored did not vary from 
// original information.
                
                if (out_line.length() != record_signature.length())
                {
                    display_message ("Error in put_signature(): Unable to attach signature to record");
                    encrypt_record.setChangeText64kB(null);
                    return 1;
                }
                try {
                    del_encrypt.delete();
                }
                catch (SecurityException e) {
                    display_message("Error in put_signature(): deleting file "+del_encrypt.toString()+" "+e.getMessage());
                    
                }
                
            }catch (IOException e) {
                display_message("Error in put_signature(): processing file "+e.getMessage());
            }
            try {
                encrypt_record.setChangeText2(form_signers+";"+userDisplayName);
                encrypt_record.save();
                
            } catch (RuntimeException e) {
                // Something went wrong while saving, show error
                 display_message("Error in put_signature(): saving encrypted data "+e.getMessage());
            }
            
            try {
                del_filename.delete();
            }
            catch (SecurityException e) {
                display_message("Error in put_signature():  deleting file "+del_filename.toString()+" "+e.getMessage());
            }
            
            return 0;
        }

/************************************************************************************/
/* decrypts_data() - This function decrypts signature from the change record.     */
/************************************************************************************/   
   
    public String decrypts_data(String displayable) {
 
        String encryption_info = null;
// Setup decryption command.
        String command;
        String sigss;
        
        String pgp_password = prompt_password ("PGP Password");
        
        if (pgp_password == null)
        {
            display_message ("Error in decrypts_data(): PGP password was not entered correctly");
        }
            
       
// Setup decrypt and sign command.
        
          command = decrypt_command+" ";
        
// Setup file name for encryption information.
        
        String file_name = temp_path+sd_id.toString();
        String encrypt_file = file_name+file_ext;
        
// Setup Batch file name 
        
        String batch_file = file_name+"decrypt"+".bat";
        String enc;
        String [] sigs = new String[10];
        
//        display_message ("Decrypt command getChangeText64kB......");
        
// Determine if the form is signed.  
        try {
            enc = encrypt_record.getChangeText64kB();
            
            if (enc == null)
            {
                display_message ("Error in decrypts_data():Record is not signed");
                return null;
            }
         
//          display_message ("signature there......");
            
            StringTokenizer fields = new StringTokenizer (enc, stars);
            
            encryption_info = fields.nextToken();
            
            String rem = enc.substring(encryption_info.length());
            
//         display_message (rem);
            
            String sig;
            while (fields.hasMoreTokens())
            {
                sig = fields.nextToken();
//                display_message (sig);
                sigs[no_sigs] = sig;
                ++no_sigs;
            }
            
            if (no_sigs == 0)
            {
              display_message ("Error in decrypt_data():Record has no signatures");
              return null;
            }
            
//           display_message ("got all signatures.....");
        } 
       catch (RuntimeException e) {
            display_message("Error in decrypt_data(): "+e.getMessage());
            return null;
        }

// Write encryption information into file.
        
        try {
            BufferedWriter d_file = new BufferedWriter(new FileWriter(encrypt_file));
            
            d_file.write(encryption_info);
            
            d_file.close();
        } catch (IOException e) {
            display_message("Error in decrypt_data(): "+e.getMessage());
        }
        
// Write decryption command into the batch file.
        
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(command);
            bat_file.write(" ");
            bat_file.write(encrypt_file);
            bat_file.write(" -u ");
            bat_file.write((int) '"');
            
            for (int v = 0; v < userDisplayName.length(); ++v) {
               bat_file.write((int) userDisplayName.charAt(v));
            }   
            bat_file.write((int) '"');
            bat_file.write (" -z "+pgp_password);
            bat_file.close();
        } catch (IOException e) {
            display_message("Error in decrypt_data(): on processing batch file "+e.getMessage());
        }

// Setup deletion of file.
        
        File del_encrypt = new File (encrypt_file);
 
        int flag = 0;
        
        if (displayable.compareTo ("DISPLAY ONLY") == 0)
        {
            flag = 1;
        }
        
// Execute decrypt command 
        
        if (execute_bat(batch_file, file_name,flag) == 0) {
 
// If successful, then call compare data (could be display signature or verify signature
// The displayable variable will determine the function.
           if (displayable.compareTo ("DISPLAY ONLY") == 0)
            {
               readin_decrypt(file_name);
               sigss = display_signature (sigs,encryption_info);
               display_message (sigss);
            }
           else if (displayable.compareTo ("delete") == 0)
           {
               delete_signature (file_name);
           }
           else if (displayable.compareTo ("add_signer") == 0)
           {
//              display_message ("calling add_signer.....");
               add_signer (sigs, encryption_info, pgp_password);
           }
           else
           {
               String validation = compare_data (file_name,displayable);
               sigss = display_signature (sigs,encryption_info);
               
//               display_message (validation+"\n"+sigss);
           }
        }
        else {
            display_message("Error in decrypt_data(): Signature not decrypted");
        }
        
        try {
            del_encrypt.delete();
        }
        catch (SecurityException e) {
            display_message("Error in decrypt_data(): Signature file "+del_encrypt.toString()+" "+e.getMessage());
        }
        return null;
    }
    
/************************************************************************************/
 /* compare_data() - This function the items in the digital signature with the      */
 /*                  current items on the change record. If the display option is   */
 /*                   specified displays the signature information.                 */
 /************************************************************************************/   
       
  public String compare_data (String file_name, String displayable)
  {
// Get the decrypted information.
      
        readin_decrypt(file_name);
     
        if (decrypted_field.indexOf(userDisplayName) < 0)
        {
            display_message (userDisplayName+" is not authorized to decrypt signature for this record");
            return null;
        }
      
// Setup to get SD fields and values from the decrypted digital signature.
      
        StringTokenizer fields = new StringTokenizer(sd_encrypt_fields,config_field_separator);
        String sd_field = null;
        String sd_value = null;
        String field = null;
        String temp = null;
        String differences = " ";
        String display_fields = " ";
        
        int same_encryption = 0;
        int start_pos_field = 0;
        int end_pos_field = 0;
        int start_pos_value = 0;
        int end_pos_value = 0;
            
// Get the SD fields and values from the decrypted digital signature.
        
        while (fields.hasMoreTokens()) {
            
            temp = decrypted_field;
            try {
                
            field = fields.nextToken();
            }
            catch (RuntimeException t){
                display_message("Error in compare_data(): "+t.getMessage());
            }

// Separator field and value.
            
            start_pos_field = decrypted_field.indexOf(field,0);
            
// If field is not part of decrypted information skip because it was newly added to
// the Configuration Item and not part of the signature. Treated as a don't care.
            
            if (start_pos_field < 0) {
                continue;
            }
 
// Separator field from value in decrypted information.
            
            end_pos_field = decrypted_field.indexOf(field_separator,start_pos_field);
            
            sd_field = decrypted_field.substring(start_pos_field,end_pos_field);
            
//            end_pos_field = end_pos_field + 2;
            
            end_pos_field = end_pos_field + field_separator.length();
            
            temp = decrypted_field.substring(end_pos_field);
            
            end_pos_value = temp.indexOf(entry_separator);
            
            sd_value = temp.substring(0,end_pos_value);
            
            if (sd_field.compareTo("ID") == 0) {
                
                display_fields = display_fields+"\n"+"Signature ID - "+sd_value;
                if (compare_fields(sd_id.toString(),sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record ID "+sd_id.toString()+"\nSignature ID "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Description") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Description -  "+sd_value;
                
                if (compare_fields(sd_description,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Description - "+sd_description+"\nSignature Description - "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Information") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Information -  "+sd_value;
                if (compare_fields(information,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Information "+information+"\nSignature Information "+sd_value;
                }
                continue;
            }
            if (sd_field.compareTo("Project") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Project -  "+sd_value;
                if (compare_fields(sd_project,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Project "+sd_project+"\nSignature Project "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Status") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Status -  "+sd_value;
                if (compare_fields(sd_status,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Status "+sd_status+"\nSignature Status "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Classification") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Classification -  "+sd_value;
                if (compare_fields(sd_classification,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Classification "+sd_classification+"\nSignature Classification "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Solution") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Solution -  "+sd_value;
               if (compare_fields(solution,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Solution "+solution+"\nSignature Solution "+sd_value;
                }
               continue;
            } 
            if (sd_field.compareTo("Manager") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Manager -  "+sd_value;
                if (compare_fields(sd_manager,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Manager "+sd_manager+"\nSignature Manager "+sd_value;
                }
                continue;
            }
            if (sd_field.compareTo("Workaround") == 0) {
               
                display_fields = display_fields+"\n"+"Signature Workaround -  "+sd_value;
                if (compare_fields(sd_workaround,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Workaround "+sd_workaround+"\nSignature Workaround "+sd_value;
                }
                continue;
            }
            
             if (sd_field.compareTo("CI") == 0) {
               
                 display_fields = display_fields+"\n"+"Signature CI -  "+sd_value;
                if (compare_fields(sd_ci,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record CI "+sd_ci+"\nSignature CI "+sd_value;
                }
                continue;
            }
        }
        
        
        File del_file = new File(file_name);
       
        try {
            del_file.delete();
        }
        catch (SecurityException e) {
            display_message("Error in compare_data(): for file "+del_file.toString()+" "+e.getMessage());
        }
       
        if (displayable.compareTo("DISPLAY ONLY") == 0)
        {
            display_message (display_fields);
            return null;
        }
        
        if (same_encryption == 0) {
            display_fields = display_fields+"\n\nSignature valid!!!";
        }
        else {
            display_fields = display_fields+"\n\nSignature invalid based on the following differences:\n"+differences;
        }
            
        return display_fields;
        
    }
/************************************************************************************/
 /* delete_signature() - This function deletes a signature associated with a change */
 /*                    record.                                                      */
 /************************************************************************************/   
       
 public int delete_signature(String file_name) {
      
// Get the decrypted information.
 /*     
       try {
            BufferedReader in = new BufferedReader(new FileReader(file_name));
            
            decrypted_field = in.readLine();
           
            in.close();
            
        }
        catch (IOException e) {
            display_message("Error in delete_signature(): "+e.getMessage());
            return 1;
        }

      if (decrypted_field.indexOf(userDisplayName) < 0)*/
     
       if (signer_or_viewer == 0)
        {
            display_message (userDisplayName+" is not authorized to delete signature for this record");
            return 0;
        }
     
     String record_signature = null;
        
    if (prompt_user ("Are you sure you want to delete signature?\n") != 0)
    {
        display_message ("Signature not deleted");
        return 1;
    }
     
    if ((record_signature = encrypt_record.getChangeText64kB()) != null)
    {
        encrypt_record.setChangeText64kB(null);
        encrypt_record.setChangeText2(null);
        encrypt_record.save();
        
        if (encrypt_record.getChangeText64kB () != null)
        {
            display_message ("Error in delete_signature(): Unable to delete signature");
            return 1;
        }
       
        display_message ("Signature for this record deleted successfully");
        return 0;
    }
    
    display_message ("No signature associated with this record");
    return 0;
    }
 /************************************************************************************/
 /* display_signature() - 
 /************************************************************************************/   

 public String display_signature (String [] signatures, String encryption_string)
 {
        String sig_file = temp_path+sd_id.toString()+".asc";
        String file_name = temp_path+sd_id.toString();
        BufferedWriter sign_to_file;
        String signers = "";
        String a_signer = null;
        String batch_file = null;
        
// Write encryption string into file.
     
        try {
            BufferedWriter file_to_encrypt = new BufferedWriter(new FileWriter(file_name));
            file_to_encrypt.write(decrypted_field);
            file_to_encrypt.close();
        
            sign_to_file = new BufferedWriter(new FileWriter(sig_file));
        }
         catch (IOException e) {
            display_message("Error in display_signature() for file : "+file_name+e.getMessage());
        }
        
        try {
        for (int i = 0; i < no_sigs; ++i)
        {
           
             if (signatures[i].indexOf("PGP") < 0)
            {
                continue;
            }
             
             if (signatures[i] == null)
             {
                 continue;
             }
             
            write_sig_to_file(sig_file, signatures[i]);
            
            batch_file = create_batch_file (decrypt_command, sig_file);
            
            if (batch_file == null)
            {
                display_message ("batch file is null");
                continue;
            }
            
            
            if (execute_bat (batch_file, sig_file, 0) == 0)
            {
              a_signer = get_signer (output_line, "\n");
              signers = signers+"\n"+a_signer; 
            }
            
        }
       }
        catch (RuntimeException e) {
            display_message("Error in display_signature(): "+e.getMessage());
        }
        
   return signers;
 }
 /************************************************************************************/
 /* add_signer() - 
 /************************************************************************************/
 public int add_signer (String [] signatures, String encryption_info, String pgp_password)
 {
        String sig_file = temp_path+sd_id.toString()+".asc";
        String file_name = temp_path+sd_id.toString();
        String signers = "";
        String batch_file = temp_path+sd_id.toString()+"sign.bat";
        byte[] buffer2 = null;
        
// Write encryption string into file.
     
//        display_message ("In add_signer.........\n");
        
        try {
            
        /*    batch_file = create_batch_file (sign_file, sig_file); */
            
          try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(sign_file);
            bat_file.write(" ");
            bat_file.write(file_name);
            bat_file.write(" -o ");
            bat_file.write(sig_file);
            bat_file.write(" -u ");
            bat_file.write((int) '"');
            
            for (int v = 0; v < userDisplayName.length(); ++v) {
               bat_file.write((int) userDisplayName.charAt(v));
            }   
            bat_file.write((int) '"');
            bat_file.write (" -z "+pgp_password);
            bat_file.close();
        } catch (IOException e) {
            display_message("Error in decrypt_data(): on processing batch file "+e.getMessage());
        }
            
//            display_message ("created batch file.....");
            
            if (batch_file == null)
            {
                display_message ("batch file is null");
                return 1;
            }
            
            if (execute_bat (batch_file, sig_file, 0) == 0)
            {
                try {
                File s = new File(sig_file);
                
                int length = (int) s.length();
                
                FileInputStream fiss = new FileInputStream(s);
                
                buffer2 = new byte[length];
                
                fiss.read(buffer2);    
                
                fiss.close();
             }
               catch (IOException e) {
            display_message("Error in add_signature() for file : "+e.getMessage());
            }
        
 //               display_message ("read in signature......");
                // the whole file is read into buffer
                
                StringBuffer sb1 = new StringBuffer(new String(buffer2));
                
// Convert encryption information into a String to be stored with SD form.
                
                String sig_out = sb1.toString();
                signatures[no_sigs] = sig_out;
                ++no_sigs;
                
//                display_message ("processing signatures.......");
                
                for (int i = 0; i < no_sigs; ++i)
                 {
           
                   if (signatures[i].indexOf("PGP") < 0)
                    {
                      continue;
                    }
             
                   if (signatures[i] == null)
                    {
                      continue;
                    }
                   
//                   display_message (signatures[i]);
                   signers = signers+stars+signatures[i];
 //                  display_message (signers);
                }
//                   display_message (signers);
                   String out_line = encryption_info+signers+stars;

// Save the encryption information with SD form.
                
//                   display_message ("writing out new signature.....");
                   
                encrypt_record.setChangeText64kB(out_line);
                encrypt_record.setChangeText2(form_signers+";"+userDisplayName);
                encrypt_record.save();
                
// Ensure that you can get the encrypted information.
                
                String record_signature = encrypt_record.getChangeText64kB();
 
                  if (debugFlag == 1)
                  {
                   try {
                        logfile.write("encrypt data = "+record_signature);
                        logfile.write ("Length of signature file = "+out_line.length());
                        logfile.write ("Length of signature attached to record = "+record_signature.length());
                   } catch (IOException e) {
                     display_message ("Error in writing to logfile "+log_file+" : "+e.getMessage());
                   }
                 }
                
// Ensure that the length of the encryption information stored did not vary from 
// original information.
                
                if (out_line.length() != record_signature.length())
                {
                    display_message ("Error in add_signature(): Unable to attach signature to record");
                    encrypt_record.setChangeText64kB(null);
                    return 1;
                }
            }
       }
        catch (RuntimeException e) {
            display_message("Error in add_signature(): "+e.getMessage());
        }
        
        display_message ("Signature for "+userDisplayName+" added");
        
   return 0;
 }
 /************************************************************************************/
 /* readin_decrypt() - 
 /************************************************************************************/
 
 public void readin_decrypt (String file_name)
 {
      try {
            BufferedReader in = new BufferedReader(new FileReader(file_name));
            
            decrypted_field = in.readLine();
           
            in.close();
            
        }
        catch (IOException e) {
            display_message("Error in compare_data(): "+e.getMessage());
            return;
        }
 }
 /* create_batch_file() - 
 /************************************************************************************/   
 public String create_batch_file (String command, String file_name)
 {  
     String batch_file = temp_path+sd_id.toString()+"verify"+".bat";
     
//     display_message ("In create batch file.....");
     
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(command);
            bat_file.write(" ");
            bat_file.write(file_name);
            bat_file.close();
        } catch (IOException e) {
            display_message("Error in decrypt_data(): on processing batch file "+e.getMessage());
        }

//      display_message ("Returning from create batch file.....");
     return batch_file;
 }
 
 /************************************************************************************/
 /* write_sig_to_file() - 
 /************************************************************************************/   
 public int write_sig_to_file (String sig_file, String signature)
 {
     try {
      
     BufferedWriter sign_to_file = new BufferedWriter(new FileWriter(sig_file));
    
     sign_to_file.write(signature);
     sign_to_file.close();
     } catch (IOException e) {
            display_message("Error in create_signature() for file : "+sig_file+e.getMessage());
        }
     return 0;
 }
/************************************************************************************/
/* is_form_approved() - This function determines if a form is approved based on    */
/*                    information on the approval sheet.                           */
/************************************************************************************/   
    public int is_form_approved()
    {
      String approval_result = encrypt_record.getApproval().getApprovalResult();
      
     /*  if (sd_status.compareTo("Approved") != 0)*/
       if (approval_result.compareTo("Approved") != 0)
        {
            return 1;
        }
        return 0;
    }
/************************************************************************************/
 /* execute_bat() - This function executes a bat file containing a security command */
 /*                    and checks for the resulting file.                           */
 /************************************************************************************/   
    
    public int execute_bat(String batch_file,String new_file,int flag) {
        String osName = System.getProperty("os.name" );
        
        String[] cmd = new String[3];
        
        try {
         /*   if( osName.equals( "Windows 2000" )) {}*/
                cmd[0] = "cmd.exe" ;
                cmd[1] = "/C" ;
                cmd[2] = batch_file;
            
            
            Runtime rt = Runtime.getRuntime();
            logfile.write("Execing " + cmd[0] + " " + cmd[1]
            + " " + cmd[2]);
            
            Process proc = rt.exec(cmd);
            // any error message?
            StreamGobbler errorGobbler = new
            StreamGobbler(proc.getErrorStream(), "ERROR");
            
            // any output?
            StreamGobbler outputGobbler = new
            StreamGobbler(proc.getInputStream(), "OUTPUT");
            
            // kick them off
            errorGobbler.start();
            outputGobbler.start();
           
            // any error???
            int exitVal = proc.waitFor();
            logfile.write("ExitValue: " + exitVal);
            
            output_line = outputGobbler.output_lines();
            
            if (debugFlag == 1)
            {
                logfile.write (output_line);
            }
           
            
        } catch (Throwable t) {
            t.printStackTrace();
        }
        File configfile = new File(new_file);
        File batch = new File(batch_file);
        
           try {
                batch.delete();
            }
            catch (SecurityException e) {
                display_message("Error in execute_bat(): for file "+batch.toString()+" "+e.getMessage());
            }
        
        if (flag == 1)
        {
            return 0;
        }
        
        // Find out if file exists, is not a directory and is readable.
        if (configfile.exists() && configfile.isFile() && configfile.canRead()) {
            return 0;
        }
        else 
        {
            return 1;
        }
   
    }
/***************************************************************************************/
 public void sleep()
 {
    try {	
                Thread.sleep(10000); 		
            }		
            catch(InterruptedException e)   		
            {      			
                System.out.println("Sleep interrupted:"+e);      		
            }
 }
/************************************************************************************/
/* compare_fields() - This function compares the value of a field in the digital   */
/*                    signature the value of the field in the change record.       */
/************************************************************************************/   
       
 public int compare_fields (String sd_form_field, String encrypted_field)
 {
     if ((sd_form_field == null) && ((encrypted_field.compareTo("null") == 0)))
     {
         return 0;
     }
     
     if ((sd_form_field == null) || (encrypted_field == null))
     {
         return 1;
     }
     
     if ((sd_form_field.compareTo(encrypted_field) == 0))
     {
         return 0;
     }
     else
     {
         return 1;
     }
 }
     
/************************************************************************************/
 /* display_message() - This function displays a given message in a dialog box.     */
 /************************************************************************************/   
       
 public void display_message (String message)
 {
    JFrame frame = new JFrame();
    JOptionPane.showMessageDialog(frame, message);
    return;
 }
 
/************************************************************************************/
 /* prompt_user() - This function prompts user for a yes, no, or cancel response in */
 /*                    a dialog box.                                                */
 /************************************************************************************/   
       
 public int prompt_user (String message)
 {
      JFrame frame = new JFrame();
     // Modal dialog with yes/no button
    int answer = JOptionPane.showConfirmDialog(frame, message);
    
    if (answer == JOptionPane.YES_OPTION) {
        return 0;
    } else if (answer == JOptionPane.NO_OPTION) {
        return 1;
    }
    
    return 1;
 }

/************************************************************************************/
 /* prompt_user_info() - This function prompts user for a SD login and password in  */
 /*                    a dialog box.                                                */
 /************************************************************************************/   

 public int prompt_user_info (String message)
 {
    JFrame source = new JFrame();
     JLabel name=new JLabel("SD Login");
     JTextField uname=new JTextField(); 
     JLabel passwd=new JLabel("SD Password");
     JTextField pword=new JPasswordField(); 
     Object[] ob={name,uname,passwd,pword}; 
     int result = JOptionPane.showConfirmDialog(source, ob, "Service Desk Login Information", JOptionPane.OK_CANCEL_OPTION);
   
  if (result == JOptionPane.OK_OPTION) {
      username= uname.getText();
     password = pword.getText();
      
     }
    
    /* display_message("Username ="+username+" password = "+password);*/
     
    return 0;
 }
 
 /************************************************************************************/
 /* prompt_password() - This function prompts user for a password response in */
 /*                    a dialog box.                                                */
 /************************************************************************************/   
  public String prompt_password (String message)
 {
     JFrame source = new JFrame();
     JLabel passwd=new JLabel("PGP Password");
     JTextField pword=new JPasswordField(); 
     Object[] ob={passwd,pword}; 
     int result = JOptionPane.showConfirmDialog(source, ob, message, JOptionPane.OK_CANCEL_OPTION);
   
  if (result == JOptionPane.OK_OPTION) {
     return (pword.getText());
     }
     
     return (null);
 }
  
  public String get_signer (String signer_info, String delimiter)
  {
       StringTokenizer fields = new StringTokenizer(signer_info,delimiter);
       String signer = "";
       String field;
       String field2;
       int sig;
       int sig1;
       
       while (fields.hasMoreTokens())
       {
          field = fields.nextToken();
          field2 = field;
          sig = field.indexOf ("Good signature");
          sig1 = field2.indexOf ("Signature made");
       
          if (sig >= 0)
          {
              signer = signer+field.substring(sig,field.length())+"\n";
              continue;
          }
          
          if (sig1 >= 0)
          {
              signer = signer+field.substring(sig1,field.length())+"\n";
              continue;
          }
       }
       
       
       return signer;
  }
  
  public void close_logfile()
  {
      try {
          
          if (debugFlag == 1)
          {
           logfile.close();
          }
          
      } catch (IOException e) {
          display_message ("Unable to close logfile: "+e.getMessage());
      }
  }
  
}
/************************************************************************************/
class StreamGobbler extends Thread {
    InputStream is;
    String type;
    String output;
    
    StreamGobbler(InputStream is, String type) {
        this.is = is;
        this.type = type;
        this.output = "";
    }
    
    public String output_lines ()
    {
        return this.output;
    }
    
    public void run() {
        try {
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line=null;
            while ( (line = br.readLine()) != null)
            {
            /*  System.out.println(type + ">" + line);  */
              
             if (line.indexOf("-z") < 0)
             {
               this.output = this.output+line+"\n";
              }
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
}

