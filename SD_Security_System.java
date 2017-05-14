import java.io.*;
import java.io.IOException;
import java.lang.*;
import java.util.*;
import java.util.zip.*;
import javax.swing.*;
import com.hp.itsm.api.*;
import com.hp.itsm.api.interfaces.*;
import com.hp.ifc.util.ApiDateUtils;

class SD_Security_System {
 
// Attributes
    
    public String Name;
    public String app_path;
    public String encrypt_command;
    public String decrypt_command;
    public String verify_command;
    public String display_command;
    public String authorize_command;
    public String file_ext;
 /***********************************************************************************/
 /* Authorize_user() - This function determines if the user has a security key to   */
 /*                    and whether the user is allowed to use the security software */
 /***********************************************************************************/   
    
    public int authorizes_user(SD_Global variables, SD_Common function, SD_Security_System sd_security, SD_Form sd_form) {
        
        String keyfile;
        String command;
        String batch_file;
      try {
 // Create name of Security user keyfile with the ID of change record
        
        keyfile = variables.temp_path+sd_form.sd_id.toString()+"keyfile";

// Setup Security System authorize command.
        
        command = sd_security.authorize_command+" ";
        
// Create name of batch file to execute Security authorize command with ID of change record
        
        batch_file = variables.temp_path+sd_form.sd_id.toString()+"getKey.bat";
      } catch (RuntimeException e) {
          function.display_message ("Error in Authorize_user: "+e.getMessage());
          return 1;
      }
// Write commands into the batch file to determine if the user has a public key.
        
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(command);
            bat_file.write((int) '"');
            
            for (int z = 0; z < sd_form.userDisplayName.length(); ++z) {
                bat_file.write((int) sd_form.userDisplayName.charAt(z));
            }
            bat_file.write((int) '"');
            bat_file.write(" ");
            
            bat_file.write((int) '"');
            for (int x = 0; x < keyfile.length(); ++x) {
                bat_file.write((int) keyfile.charAt(x));
            }
            bat_file.write((int) '"');
            
            bat_file.close();
        } catch (IOException e) {
            function.display_message ("Error in authorize_user(): "+e.getMessage());
        }
   
// Setup to delete the key file. The batch file will be deleted in the execute_bat function
        
        File del_key = new File(keyfile);
  
// Execute the batch file and check to see if the user has a public/private key.
        
        if (function.execute_bat(variables,batch_file, keyfile,0) == 0) {
 
// Delete the keyfile.
            
            try {
                del_key.delete();
            }
            catch (SecurityException e) {
                function.display_message("Error in authorizes_user(): file "+del_key.toString()+" "+e.getMessage());
            }
            return 0;
        }
        else {
            
// Delete the keyfile.
            
            try {
                del_key.delete();
            }
            catch (SecurityException e) {
                function.display_message("Error in authorizes_user(): file "+del_key.toString()+" "+e.getMessage());
            }
            function.display_message("Error in authorizes_user(): User information not defined in security software");
            return 1;
        }
  }
    
}
