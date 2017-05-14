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

class SD_Signature {
 

/************************************************************************************/
 /* create_signature() - This function creates an digital signature based on        */
 /*                    various fields on the SD change record.                      */
 /************************************************************************************/   
           
public int create_signature(SD_Global variables, SD_Common function, SD_Security_System sd_security, SD_Form sd_form) {
    
    StringTokenizer fields;
    String sd_field = null;
    String encryption_string;
    String null_fields = " ";
    String record;
  try { 
    if (variables.signer_or_viewer == 0)
    {
        function.display_message ("Warning: "+sd_form.userDisplayName+" is not an authorized signer");
        return 0;
    }
   
   // Determine if user has signed form already.
         
         if (sd_form.form_signers != null)
          {
           if (sd_form.form_signers.indexOf(sd_form.userDisplayName) > -1)
            {
             function.display_message ("Warning: "+sd_form.userDisplayName+" has already signed form");
             return 0;
            }
          }
// Setup array to contain the list of SD fields that should be in the digital signature.
    
        fields = new StringTokenizer(sd_form.sd_encrypt_fields,variables.config_field_separator);
 
// Temporary field to hold SD fields from the Configuration Item form.
        
        sd_field = null;
  
// String to hold the fields and values from the SD form.
        
        encryption_string = null+variables.entry_separator;
        null_fields = " ";

// If the form is already signed, decrypt signature(s) and fields before adding new signature.
        
       record = sd_form.encrypt_record.getChangeText64kB();
       
        if (record != null)
        {
                decrypts_data (variables, function,sd_security,sd_form,"add_signer");
                return 0;
        }
     }catch (RuntimeException e) {
                    function.display_message ("Error in Create_Signature for getChangeText64KB: "+e.getMessage());
                    return 0;
      }
       
// Cycle through list of SD fields from Configuration Item form. Add field name and
// value to the encryption_string. In addition, keep track of those fields that do not
// have values.
     
    try {
        encryption_string = sd_form.userDisplayName+variables.entry_separator;
        
        while (fields.hasMoreTokens()) {
            sd_field = fields.nextToken();


            if (sd_field.compareTo("ID") == 0) {
                encryption_string = encryption_string+"ID"+variables.field_separator+sd_form.sd_id.toString()+variables.entry_separator;
            }
            
            if (sd_field.compareTo("Description") == 0) {
                
                if (sd_form.sd_description == null)
                {
                    null_fields = null_fields+"\n"+"Description";
                }
                encryption_string = encryption_string+"Description"+variables.field_separator+sd_form.sd_description+variables.entry_separator;
            }
            
            if (sd_field.compareTo("Information") == 0) {
                
                if (sd_form.information == null)
                {
                    null_fields = null_fields+"\n"+"Information";
                }
                 
                encryption_string = encryption_string+"Information"+variables.field_separator+sd_form.information+variables.entry_separator;
            }
            if (sd_field.compareTo("Project") == 0) {
                
                if (sd_form.sd_project == null)
                {
                    null_fields = null_fields+"\n"+"Project";
                }
                
                encryption_string = encryption_string+"Project"+variables.field_separator+sd_form.sd_project+variables.entry_separator;
            }
            
            if (sd_field.compareTo("Status") == 0) {
                
                if (sd_form.sd_status == null)
                {
                    null_fields = null_fields+"\n"+"Status";
                }
                
                encryption_string = encryption_string+"Status"+variables.field_separator+sd_form.sd_status+variables.entry_separator;
            }
            
            if (sd_field.compareTo("Classification") == 0) {
                
                if (sd_form.sd_classification == null)
                {
                    null_fields = null_fields+"\n"+"Classification";
                }
                
                encryption_string = encryption_string+"Classification"+variables.field_separator+sd_form.sd_classification+variables.entry_separator;
            }
            
            if (sd_field.compareTo("Solution") == 0) {
                
                if (sd_form.solution == null)
                {
                    null_fields = null_fields+"\n"+"Solution";
                }
                
                encryption_string = encryption_string+"Solution"+variables.field_separator+sd_form.solution+variables.entry_separator;
            }
            
            if (sd_field.compareTo("Manager") == 0) {
                
                if (sd_form.sd_manager == null)
                {
                    null_fields = null_fields+"\n"+"Manager";
                }
                
                encryption_string = encryption_string+"Manager"+variables.field_separator+sd_form.sd_manager+variables.entry_separator;
            }
            
             if (sd_field.compareTo("Workaround") == 0) {
                 
                if (sd_form.sd_workaround == null)
                {
                    null_fields = null_fields+"\n"+"Workaround";
                }
                encryption_string = encryption_string+"Workaround"+variables.field_separator+sd_form.sd_workaround+variables.entry_separator;
            }
            
             if (sd_field.compareTo("CI") == 0) {
                 
                if (sd_form.sd_ci == null)
                {
                    null_fields = null_fields+"\n"+"CI";
                }
                encryption_string = encryption_string+"CI"+variables.field_separator+sd_form.sd_ci+variables.entry_separator;
            }
        }
    } catch (RuntimeException e) {
        function.display_message ("Error in create_signature(): "+e.getMessage());
        return 1;
    }
// If there were fields that have null value, allow user to either continue with creating
// signature or aborting.
        
        if (null_fields.length() > 1)
        {
            if (function.prompt_user ("The following fields below contain no information:\n"+null_fields+"\n\n"+"Do you still want to sign the form?\n") != 0)
            {
                return 1;
            }
        }
        
          if (variables.debugFlag == 1)
           {
             try {
              variables.logfile.write("Encryption string = "+encryption_string);
             } catch (IOException e) {
                 function.display_message ("Error in writing to logfile "+variables.log_file+" : "+e.getMessage());
             }
         }
        
// Create name of the file that will hold the encryption string to be encrypted
// by the security software.
        
        String sig_file = variables.temp_path+sd_form.sd_id.toString()+".sig.asc";
        String file_name = variables.temp_path+sd_form.sd_id.toString();
        
        
// Write encryption string into file.
        
        try {
            BufferedWriter file_to_encrypt = new BufferedWriter(new FileWriter(file_name));
            file_to_encrypt.write(encryption_string);
            file_to_encrypt.close();
        }
        catch (IOException e) {
            function.display_message("Error in create_signature() for file : "+file_name+e.getMessage());
        }
   
        String pgp_password = function.prompt_password ("PGP Password");
        
        if (pgp_password == null)
         {
            function.display_message ("Error in create_signature(): PGP password was not entered correctly");
         }
        
// Setup encrypt and sign command.
        
        String sign_command = variables.sign_file+" ";
        String encrypt_command = sd_security.encrypt_command+" ";
        
// Setup batch file name to execute encrypt and sign command.
        
        String batch_file = file_name+"encrypt"+".bat";
        
// Write encrypt and sign commands into the batch file.
        
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
  
// First write out signature command.
            
            bat_file.write(sign_command);
            bat_file.write(" -o ");
            bat_file.write(" ");
            
            bat_file.write((int) '"');
            
            for (int s = 0; s < sig_file.length(); ++s) {
               bat_file.write((int) sig_file.charAt(s));
            }        
            bat_file.write((int) '"');
            
            bat_file.write(" ");
            bat_file.write((int) '"');
            for (int f = 0; f < file_name.length(); ++f) {
               bat_file.write((int) file_name.charAt(f));
            }        
            bat_file.write((int) '"');
            
            bat_file.write(" ");
            
            bat_file.write(" -u ");
            bat_file.write((int) '"');
            
            for (int v = 0; v < sd_form.userDisplayName.length(); ++v) {
               bat_file.write((int) sd_form.userDisplayName.charAt(v));
            }   
           bat_file.write((int) '"');
           bat_file.write (" -z "+pgp_password);
           bat_file.write ("\n");

// The write out encryption command with all users of the Encryption CI.
// This will those users to view the signatures.
            
            bat_file.write(encrypt_command);
            bat_file.write(" ");
            
            bat_file.write((int) '"');
            for (int f = 0; f < file_name.length(); ++f) {
               bat_file.write((int) file_name.charAt(f));
            }        
            bat_file.write((int) '"');
            
            bat_file.write(" ");
            
            String rep;
            
// Adding Encryption CI users.
            
            for (int y = 0; y < sd_form.users_ci.length; ++y)
            {
                rep = sd_form.users_ci[y].getAccount().getDisplayName();
                
                bat_file.write((int) '"');
            
               for (int z = 0; z < rep.length(); ++z) {
                bat_file.write((int) rep.charAt(z));
               }
                 bat_file.write((int) '"');
                 bat_file.write(" ");
            } 

// Add signer and passphrase
          
            bat_file.write(" -u ");
            bat_file.write((int) '"');
            
            for (int v = 0; v < sd_form.userDisplayName.length(); ++v) {
               bat_file.write((int) sd_form.userDisplayName.charAt(v));
            }   
            bat_file.write((int) '"');
            
            bat_file.write (" -z "+pgp_password);
            
            bat_file.close();
        } catch (IOException e) {
           function.display_message("Error in create_signature(): file "+batch_file+" "+e.getMessage());
        }
        
// Setup name of resulting file from encrypt and sign command.
        
        String encrypt_file = file_name+sd_security.file_ext;

// Setup files for deletion. batch file will be deleted by execute_bat function.
        
        File del_filename = new File(file_name);
        File del_encrypt = new File(encrypt_file);
        File del_sigfile = new File (sig_file);

// Execute encrypt and sign command and check for resulting file.
        
        if (function.execute_bat(variables,batch_file, encrypt_file,0) == 0) {
            put_signature (variables, function, sd_form, file_name,encrypt_file,sig_file);
            function.display_message ("Signature for "+sd_form.userDisplayName+" successfully added to record");
            
             try {
                del_sigfile.delete();
            }
            catch (SecurityException e) {
                function.display_message("Error in create_signature(): file "+del_sigfile.toString()+" "+e.getMessage());
            }
            
            return 0;
        }
        else {
            function.display_message ("Error in create_signature(): Unable to encrypt fields");

// Delete file            
            try {
                del_encrypt.delete();
            }
            catch (SecurityException e) {
                function.display_message("Error in create_signature(): file "+del_encrypt.toString()+" "+e.getMessage());
            }
            
             try {
                del_filename.delete();
            }
            catch (SecurityException e) {
                function.display_message("Error in create_signature(): file "+del_filename.toString()+" "+e.getMessage());
            }
            
            try {
                del_sigfile.delete();
            }
            catch (SecurityException e) {
                function.display_message("Error in create_signature(): file "+del_sigfile.toString()+" "+e.getMessage());
            }
            return 1;
        }
    }

/************************************************************************************/
 /* put_signature() - This function attaches the digital signature to the change    */
 /*                   record.                                                      */
 /************************************************************************************/   
       
    public int put_signature (SD_Global variables, SD_Common function, SD_Form sd_form, String file_name, String encrypt_file, String sig_file)
    {
        File del_filename = null;;
        File del_encrypt = null;
// Setup file for deletion.
       try {
        del_filename = new File(file_name);
        del_encrypt = new File(encrypt_file);
       } catch (RuntimeException e) {
           function.display_message ("Error in put_signature: "+e.getMessage());
       }
// Read-in encrypted information from file to be placed in the SD form.
        
           try {
                
                File f = new File(encrypt_file);
                
                int length = (int) f.length();
                
                FileInputStream fis = new FileInputStream(f);
                
                byte[] buffer = new byte[length];
                
                fis.read(buffer);    
                
                fis.close();
                
// Read-in signature information from file to be placed in the SD form.     
                
                File s = new File(sig_file);
                
                length = (int) s.length();
                
                FileInputStream fiss = new FileInputStream(s);
                
                byte[] buffer2 = new byte[length];
                
                fiss.read(buffer2);    
                
                fiss.close();
// the whole file is read into buffer for encryption and signature information as armored
// ascii format.
                
                StringBuffer sb = new StringBuffer(new String(buffer));
                StringBuffer sb1 = new StringBuffer(new String(buffer2));
                
// Convert encryption and signature information into a String to be stored with SD form.
                
                String fields_out = sb.toString();
                String sig_out = sb1.toString();

                String all_signers = sd_form.form_signers+";"+sd_form.userDisplayName;
// Create string to be written into SD form.
                
                String out_line = all_signers+"\n"+variables.stars+fields_out+"\n"+variables.stars+sig_out+"\n"+variables.stars;

// Save the encryption information with SD form.
                
                sd_form.encrypt_record.setChangeText64kB(out_line);
                
// Ensure that you can get the encrypted information.
                
                String record_signature = sd_form.encrypt_record.getChangeText64kB();

                 variables.debugFlag = 1;
// If the debug flag is set write out information about the information stored into logfile.
                  if (variables.debugFlag == 1)
                  {
                   try {
                        variables.logfile.write("encrypt data = "+record_signature);
                        variables.logfile.write ("\nLength of signature file = "+out_line.length());
                        variables.logfile.write ("\nLength of signature attached to record = "+record_signature.length());
                   } catch (IOException e) {
                     function.display_message ("Error in writing to logfile "+variables.log_file+" : "+e.getMessage());
                   }
                 }
                
// Ensure that the length of the encryption and signature information stored did not vary from 
// original information.
                
                if (out_line.length() != record_signature.length())
                {
                    function.display_message ("Error in put_signature(): Unable to attach signature to record");
                    sd_form.encrypt_record.setChangeText64kB(null);
                    return 1;
                }
                try {
                    del_encrypt.delete();
                }
                catch (SecurityException e) {
                    function.display_message("Error in put_signature(): deleting file "+del_encrypt.toString()+" "+e.getMessage());
                    
                }
                
            }catch (IOException e) {
                function.display_message("Error in put_signature(): processing file "+e.getMessage());
            }  
            try {
                del_filename.delete();
            }
            catch (SecurityException e) {
                function.display_message("Error in put_signature():  deleting file "+del_filename.toString()+" "+e.getMessage());
            }
            
            sd_form.encrypt_record.save();
            return 0;
        }
    
/************************************************************************************/
 /* compare_data() - This function the items in the digital signature with the      */
 /*                  current items on the change record. If the display option is   */
 /*                   specified displays the signature information.                 */
 /************************************************************************************/   
       
  public String compare_data (SD_Global variables, SD_Common function, SD_Form sd_form, String file_name, String displayable)
  {
// Get the decrypted information.
      try {
        function.readin_decrypt(variables,file_name);
     
       if (variables.signer_or_viewer == 0)
        {
            function.display_message (sd_form.userDisplayName+" is not authorized to decrypt signature for this record");
            return null;
        }
      } catch (RuntimeException e) {
          function.display_message ("Error in Compare_data(): "+e.getMessage());
          return null;
      }
// Setup to get SD fields and values from the decrypted digital signature.
      
        StringTokenizer fields = new StringTokenizer(sd_form.sd_encrypt_fields,variables.config_field_separator);
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
       try { 
        while (fields.hasMoreTokens()) {
            temp = variables.decrypted_field;
            try {
                
            field = fields.nextToken();
            }
            catch (RuntimeException t){
                function.display_message("Error in compare_data(): "+t.getMessage());
            }

// Separator field and value.

            start_pos_field = variables.decrypted_field.indexOf(field,0);
            
// If field is not part of decrypted information skip because it was newly added to
// the Configuration Item and not part of the signature. Treated as a don't care.
            
            if (start_pos_field < 0) {
                continue;
            }
 
// Separator field from value in decrypted information.
            
            end_pos_field = variables.decrypted_field.indexOf(variables.field_separator,start_pos_field);
            
            sd_field = variables.decrypted_field.substring(start_pos_field,end_pos_field);
            
            end_pos_field = end_pos_field + variables.field_separator.length();
            
            temp = variables.decrypted_field.substring(end_pos_field);
            
            end_pos_value = temp.indexOf(variables.entry_separator);
            
            sd_value = temp.substring(0,end_pos_value);
            
            if (sd_field.compareTo("ID") == 0) {
                
                display_fields = display_fields+"\n"+"Signature ID - "+sd_value;
                if (function.compare_fields(sd_form.sd_id.toString(),sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record ID "+sd_form.sd_id.toString()+"\nSignature ID "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Description") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Description -  "+sd_value;
                
                if (function.compare_fields(sd_form.sd_description,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Description - "+sd_form.sd_description+"\nSignature Description - "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Information") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Information -  "+sd_value;
                if (function.compare_fields(sd_form.information,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Information "+sd_form.information+"\nSignature Information "+sd_value;
                }
                continue;
            }
            if (sd_field.compareTo("Project") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Project -  "+sd_value;
                if (function.compare_fields(sd_form.sd_project,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Project "+sd_form.sd_project+"\nSignature Project "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Status") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Status -  "+sd_value;
                if (function.compare_fields(sd_form.sd_status,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Status "+sd_form.sd_status+"\nSignature Status "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Classification") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Classification -  "+sd_value;
                if (function.compare_fields(sd_form.sd_classification,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Classification "+sd_form.sd_classification+"\nSignature Classification "+sd_value;
                }
                continue;
            }
            
            if (sd_field.compareTo("Solution") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Solution -  "+sd_value;
               if (function.compare_fields(sd_form.solution,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Solution "+sd_form.solution+"\nSignature Solution "+sd_value;
                }
               continue;
            } 
            if (sd_field.compareTo("Manager") == 0) {
                
                display_fields = display_fields+"\n"+"Signature Manager -  "+sd_value;
                if (function.compare_fields(sd_form.sd_manager,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Manager "+sd_form.sd_manager+"\nSignature Manager "+sd_value;
                }
                continue;
            }
            if (sd_field.compareTo("Workaround") == 0) {
               
                display_fields = display_fields+"\n"+"Signature Workaround -  "+sd_value;
                if (function.compare_fields(sd_form.sd_workaround,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record Workaround "+sd_form.sd_workaround+"\nSignature Workaround "+sd_value;
                }
                continue;
            }
            
             if (sd_field.compareTo("CI") == 0) {
               
                 display_fields = display_fields+"\n"+"Signature CI -  "+sd_value;
                if (function.compare_fields(sd_form.sd_ci,sd_value) != 0) {
                    same_encryption = 1;
                    differences = differences+"\n"+"Record CI "+sd_form.sd_ci+"\nSignature CI "+sd_value;
                }
                continue;
            }
        }
       } catch (RuntimeException e) {
           function.display_message ("Error in Compare_Data(): "+e.getMessage());
           return null;
       }
        File del_file = new File(file_name);
       
        try {
            del_file.delete();
        }
        catch (SecurityException e) {
            function.display_message("Error in compare_data(): for file "+del_file.toString()+" "+e.getMessage());
        }
      try {
        if (displayable.compareTo("DISPLAY ONLY") == 0)
        {
            function.display_message (display_fields);
            return null;
        }
        
        if (same_encryption == 0) {
            display_fields = display_fields+"\n\nSignature valid!!!";
        }
        else {
            display_fields = display_fields+"\n\nSignature invalid based on the following differences:\n"+differences;
        }
            
        return display_fields;
      } catch (RuntimeException e) {
          function.display_message ("Error in Compare_Data(): "+e.getMessage());
          return null;
      }
        
    }
/************************************************************************************/
 /* delete_signature() - This function deletes a signature associated with a change */
 /*                    record.                                                      */
 /************************************************************************************/   
       
 public int delete_signature(SD_Global variables, SD_Common function, SD_Form sd_form, String file_name) {
      
  try {  
 
// Is this user authorized to delete the signature. Only signers have that capability.
      
   if (variables.signer_or_viewer == 0)
    {
      function.display_message (sd_form.userDisplayName+" is not authorized to delete signature for this record");
      return 0;
    }
     
     String record_signature = null;

// Prompt user to ensure they want to delete the signature.
     
    if (function.prompt_user ("Are you sure you want to delete signature?\n") != 0)
    {
        function.display_message ("Signature not deleted");
        return 1;
    }

// Wipe out digital signature and list of signers and save record.
     
    if ((record_signature = sd_form.encrypt_record.getChangeText64kB()) != null)
    {
        sd_form.encrypt_record.setChangeText64kB(null);
        sd_form.encrypt_record.setChangeText2(null);
        sd_form.encrypt_record.save();

// Readin signature to ensure that it has been wiped out.
        
        if (sd_form.encrypt_record.getChangeText64kB () != null)
        {
            function.display_message ("Error in delete_signature(): Unable to delete signature");
            return 1;
        }

// Readin list of signers to ensure that it has been wiped out.
        
        if (sd_form.encrypt_record.getChangeText2 () != null)
        {
            function.display_message ("Error in delete_signature(): Unable to delete list of signers");
            return 1;
        }
       
        function.display_message ("Signature for this record deleted successfully");
        return 0;
    }
    
    function.display_message ("No signature associated with this record");
    return 0;
  } catch (RuntimeException e) {
      function.display_message ("Error in Delete_Signature: "+e.getMessage());
      return 1;
  }
 }
 /************************************************************************************/
 /* display_signature() - This function returns all signature associated with the   */
 /*                       encryption information.
 /************************************************************************************/   

 public String display_signature (SD_Global variables, SD_Common function, SD_Security_System sd_security, SD_Form sd_form, String [] signatures, String encryption_string)
 {
        String sig_file = variables.temp_path+sd_form.sd_id.toString()+sd_security.file_ext;
        String file_name = variables.temp_path+sd_form.sd_id.toString();
        BufferedWriter sign_to_file;
        String signers = "";
        String a_signer = null;
        String batch_file = null;
        
// Write encryption string into file.
     
        try {
            BufferedWriter file_to_encrypt = new BufferedWriter(new FileWriter(file_name));
            file_to_encrypt.write(variables.decrypted_field);
            file_to_encrypt.close();
        
            sign_to_file = new BufferedWriter(new FileWriter(sig_file));
        }
         catch (IOException e) {
            function.display_message("Error in display_signature() for file : "+file_name+e.getMessage());
        }
        
       try {

// Get all signatures associated with encrypted information.
           
        for (int i = 0; i < variables.no_sigs; ++i)
        {
// Skip data that is not signature.
             if (signatures[i].indexOf(sd_security.Name) < 0)
            {
                continue;
            }
// Skip null data.             
             if (signatures[i] == null)
             {
                 continue;
             }

// Write signature data into file to be converted into readable ascii information.
             
            write_sig_to_file(variables, function,sig_file, signatures[i]);
            
// Create batch file with commands to convert signature into readable ascii information.
            
            batch_file = function.create_batch_file (variables, sd_form.sd_id, sd_security.decrypt_command, sig_file);
            
            if (batch_file == null)
            {
                function.display_message ("Error in display_signature(): batch file is null");
                continue;
            }
            
// Execute batch file, get Signer's name, and add signer's information to list of signers.
            
            if (function.execute_bat (variables,batch_file, sig_file, 0) == 0)
            {
              a_signer = get_signer (function, variables.output_line, "\n");
              signers = signers+"\n"+a_signer; 
            }
            
        }
       }
        catch (RuntimeException e) {
            function.display_message("Error in display_signature(): "+e.getMessage());
        }
        
   return signers;
 }
 /************************************************************************************/
 /* add_signer() - This function will add a signer to an already signed SD form      */
 /************************************************************************************/
 public int add_signer (SD_Global variables, SD_Common function, SD_Form sd_form, SD_Security_System sd_security, String [] signatures, String encryption_info, String pgp_password)
 {
        String sig_file = variables.temp_path+sd_form.sd_id.toString()+sd_security.file_ext;
        String file_name = variables.temp_path+sd_form.sd_id.toString();
        String signers = "";
        String batch_file = variables.temp_path+sd_form.sd_id.toString()+"sign.bat";
        byte[] buffer2 = null;
        
// Write encryption string into file.
     
//        display_message ("In add_signer.........\n");
        
        try {
            
          try {
              
// Create the batch file with commands to create the signature.
              
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            bat_file.write((int) '"');
            for (int s = 0; s < variables.sign_file.length(); ++s) {
               bat_file.write((int) variables.sign_file.charAt(s));
            }   
            bat_file.write((int) '"');
            bat_file.write(" ");
            
            bat_file.write((int) '"');
            for (int f = 0; f < file_name.length(); ++f) {
               bat_file.write((int) file_name.charAt(f));
            }   
            bat_file.write((int) '"');
            bat_file.write(" ");
            bat_file.write(" -o ");
            
            bat_file.write((int) '"');
            for (int s = 0; s < sig_file.length(); ++s) {
               bat_file.write((int) sig_file.charAt(s));
            }   
            
            bat_file.write((int) '"');
            bat_file.write(" ");
            bat_file.write(" -u ");
            bat_file.write((int) '"');
            
            for (int v = 0; v < sd_form.userDisplayName.length(); ++v) {
               bat_file.write((int) sd_form.userDisplayName.charAt(v));
            }   
            bat_file.write((int) '"');
            bat_file.write (" -z "+pgp_password);
            bat_file.close();
        } catch (IOException e) {
            function.display_message("Error in decrypt_data(): on processing batch file "+e.getMessage());
        }
   
// Determine if batch file was created.
          
            if (batch_file == null)
            {
                function.display_message ("Error in Add_signer(): batch file is null");
                return 1;
            }

// Execute batch file.
          
            if (function.execute_bat (variables,batch_file, sig_file, 0) == 0)
            {
                try {
                    
// Readin the signature (armored ascii format) to be added to the list of signatures.
                    
                File s = new File(sig_file);
                
                int length = (int) s.length();
                
                FileInputStream fiss = new FileInputStream(s);
                
                buffer2 = new byte[length];
                
                fiss.read(buffer2);    
                
                fiss.close();
             }
               catch (IOException e) {
            function.display_message("Error in add_signer() for file : "+e.getMessage());
            }
        
                // the whole file is read into buffer
                
                StringBuffer sb1 = new StringBuffer(new String(buffer2));
                
// Convert signature information into a String to be stored with SD form and add to list.
                
                String sig_out = sb1.toString();
                signatures[variables.no_sigs] = sig_out;
                ++variables.no_sigs;
                
                for (int i = 0; i < variables.no_sigs; ++i)
                 {

// Skip non signature data
                     
                   if (signatures[i].indexOf(sd_security.Name) < 0)
                    {
                      continue;
                    }

// Skip null data
                   
                   if (signatures[i] == null)
                    {
                      continue;
                    }
                   

// Append signature to format to be stored in SD form with encryption information.
                   
                   signers = signers+variables.stars+signatures[i];
 //                  display_message (signers);
                }
                
// Create string with encryption and signature information.
                
                   String out_line = encryption_info+signers+variables.stars;

// Add signers to list of information with SD form.
                   String all_signers = sd_form.form_signers+";"+sd_form.userDisplayName;
// Create string to be written into SD form.
                   String out_line1 = all_signers+"\n"+variables.stars+out_line;

// Write encryption information into SD Form.
                   
                sd_form.encrypt_record.setChangeText64kB(out_line1);
                sd_form.encrypt_record.save();
                
// Ensure that you can get the encrypted information.
                
                String record_signature = sd_form.encrypt_record.getChangeText64kB();
 
// If debug flag set write detail information into file.
                
                  if (variables.debugFlag == 1)
                  {
                   try {
                        variables.logfile.write("encrypt data = "+record_signature);
                        variables.logfile.write ("Length of signature file = "+out_line.length());
                        variables.logfile.write ("Length of signature attached to record = "+record_signature.length());
                   } catch (IOException e) {
                     function.display_message ("Error in writing to logfile "+variables.log_file+" : "+e.getMessage());
                   }
                 }
                
// Ensure that the length of the encryption information stored did not vary from 
// original information.
                
                if (out_line1.length() != record_signature.length())
                {
                    function.display_message ("Error in add_signer(): Unable to attach new signature to record");
                    sd_form.encrypt_record.setChangeText64kB(sd_form.form_signers+"\n"+variables.stars+out_line);
                    return 1;
                }
            }
       }
        catch (RuntimeException e) {
            function.display_message("Error in add_signer(): "+e.getMessage());
        }
        
        function.display_message ("Signature for "+sd_form.userDisplayName+" added");
        
   return 0;
 }
  
 /************************************************************************************/
 /* write_sig_to_file() - This function writes the signature stored in the SD form   */
 /*                       into a file so it can be converted into a readable ascii   */
 /*                       format.                                                    */
 /************************************************************************************/   
public int write_sig_to_file (SD_Global variables, SD_Common function, String sig_file, String signature)
 {
     try {
      
     BufferedWriter sign_to_file = new BufferedWriter(new FileWriter(sig_file));
    
     sign_to_file.write(signature);
     sign_to_file.close();
     } catch (IOException e) {
            function.display_message("Error in write_sig_to_file() for file : "+sig_file+e.getMessage());
        }
     return 0;
 }
 
 
 /************************************************************************************/
 /* get_signer() - This function extracts the signer information stored in the SD    */
 /*                form.                                                             */
 /************************************************************************************/
  public String get_signer (SD_Common function, String signer_info, String delimiter)
  {
       StringTokenizer fields = new StringTokenizer(signer_info,delimiter);
       String signer = "";
       String field;
       String field2;
       int sig;
       int sig1;
       
     try { 
 
// Get signers
       while (fields.hasMoreTokens())
       {
          field = fields.nextToken();
          field2 = field;
          sig = field.indexOf ("Good signature");
          sig1 = field2.indexOf ("Signature made");
       
// Get signers name and format output
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
     } catch (RuntimeException e) {
         function.display_message ("Error in get_Signer(): "+e.getMessage());
         return null;
     }
  }
  
/************************************************************************************/
/* decrypts_data() - This function decrypts signature from the change record.     */
/************************************************************************************/   
   
    public String decrypts_data(SD_Global variables, SD_Common function, SD_Security_System sd_security, SD_Form sd_form, String displayable) {
 
        String encryption_info = null;
        String command;
        String sigss;
        String pgp_password;
       
// Setup decrypt and sign command.
        
        command = sd_security.decrypt_command+" ";
        
// Setup file name for encryption information.
        
       String file_name = variables.temp_path+sd_form.sd_id.toString();
       String encrypt_file = file_name+sd_security.file_ext;
// Setup Batch file name 
        
        String batch_file = file_name+"decrypt"+".bat";
        String enc;
        String [] sigs = new String[10];
        
// Determine if the form is signed.  
        try {
            enc = sd_form.encrypt_record.getChangeText64kB();
            
            if (enc == null)
            {
                function.display_message ("Error in decrypts_data():Record is not signed");
                return null;
            }
 // This option will show the list of people who have currently signed the record
 // No decryption is required to see the list of signers.
            
            if (displayable.compareTo("SIGNERS ONLY") == 0)
            { 
              StringTokenizer all_signers = new StringTokenizer (sd_form.form_signers, variables.config_field_separator);
              
              String list_of_signers = "The following individuals have signed this record: \n";
              
              all_signers.nextToken();
              
              while (all_signers.countTokens() != 0)
              {
                list_of_signers += all_signers.nextToken();
              }
              function.display_message(list_of_signers);
              return null;
            }
            
// Get the encryption password from user.
        pgp_password = null;
//       pgp_password = function.prompt_password ("PGP Password");
// If this is add Signature option then pass phrase is needed.
      
//    if (displayable.compareTo("add_signer") == 0)
//     {
         pgp_password = function.prompt_password ("PGP Password");
         
       if (pgp_password == null)
       {
            function.display_message ("Error in decrypts_data(): PGP password was not entered correctly");
           return null;
        }
//     }
   // Parse out encryption and signature information that was stored in the SD form.
         
            StringTokenizer fields = new StringTokenizer (enc, variables.stars);
   
   // First field is always encryption information.
            String ignore = fields.nextToken();
            
            encryption_info = fields.nextToken();
   
   // Remaining information is the signature information.
            
            String rem = enc.substring(encryption_info.length());
            
            String sig;
   
   // Parse signatures and make a list.
            
            while (fields.hasMoreTokens())
            {
                sig = fields.nextToken();
                sigs[variables.no_sigs] = sig;
                ++variables.no_sigs;
            }
            
   // If no signatures, then something wrong!
            
            if (variables.no_sigs == 0)
            {
              function.display_message ("Error in decrypt_data():Record has no signatures");
              return null;
            }
            
            
        } 
       catch (RuntimeException e) {
            function.display_message("Error in decrypt_data(): "+e.getMessage());
            return null;
        }

// Write encryption information into file.
        
        try {
            BufferedWriter d_file = new BufferedWriter(new FileWriter(encrypt_file));
            
            d_file.write(encryption_info);
            
            d_file.close();
        } catch (IOException e) {
            function.display_message("Error in decrypt_data(): "+e.getMessage());
        }
        
// Write decryption command into the batch file.
        
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(command);
            bat_file.write(" ");
             bat_file.write((int) '"');
            
            for (int v = 0; v < encrypt_file.length(); ++v) {
               bat_file.write((int) encrypt_file.charAt(v));
            }   
           bat_file.write((int) '"');
            bat_file.write(" -u ");
            bat_file.write((int) '"');
            
            for (int v = 0; v < sd_form.userDisplayName.length(); ++v) {
               bat_file.write((int) sd_form.userDisplayName.charAt(v));
            }   
           bat_file.write((int) '"');
            bat_file.write (" -z "+pgp_password);
            bat_file.close();
        } catch (IOException e) {
            function.display_message("Error in decrypt_data(): on processing batch file "+e.getMessage());
        }

        
// Setup deletion of file.
        
        File del_encrypt = new File (encrypt_file);
        File del_file_name = new File (file_name);
        
     try {
        int flag = 0;
        
        if (displayable.compareTo ("DISPLAY ONLY") == 0)
        {
            flag = 1;
        }
        
// Execute decrypt command 
        
        
        if (function.execute_bat(variables,batch_file, file_name,flag) == 0) {
 
// The displayable variable will determine the function. Display Signatures Only!
            
           if (displayable.compareTo ("DISPLAY ONLY") == 0)
            {
               function.readin_decrypt(variables,file_name);
               sigss = display_signature (variables,function,sd_security, sd_form,sigs,encryption_info);
               function.display_message (sigss);
            }
// Delete Signature
           else if (displayable.compareTo ("delete") == 0)
           {
               delete_signature (variables, function, sd_form, file_name);
           }
// Add signature
           else if (displayable.compareTo ("add_signer") == 0)
           {
               add_signer (variables, function, sd_form, sd_security, sigs, encryption_info, pgp_password);
           }
// Display Signature and encryption information.
           else
           {
               String validation = compare_data (variables,function,sd_form, file_name,displayable);
// If validation is null then problem has been noted. Time to leave!               
               if (validation == null)
               {
                   return null;
               }
               sigss = display_signature (variables, function, sd_security, sd_form, sigs,encryption_info);
          
               function.display_message (validation+"\n"+sigss);
           }
        }
// Execution of batch file failed.
        else {
            function.display_message("Error in decrypt_data(): Signature not decrypted");
        }
     } catch (RuntimeException e) {
         function.display_message ("Error in decrypt_data(): "+e.getMessage());
     }
     
        try {
            del_encrypt.delete();
        }
        catch (SecurityException e) {
            function.display_message("Error in decrypt_data(): Signature file "+del_encrypt.toString()+" "+e.getMessage());
        }
        
         try {
            del_file_name.delete();
        }
        catch (SecurityException e) {
            function.display_message("Error in decrypt_data(): Signature file "+del_file_name.toString()+" "+e.getMessage());
        }
        
        return null;
    }
    
}



