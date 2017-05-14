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
import java.util.regex.Pattern;
import java.util.regex.Matcher;

class SD_Common {
 
 /************************************************************************************/
 /* readin_decrypt() - Thus function reads in the decrypted version of the SD fields */
 /************************************************************************************/
 
 public void readin_decrypt (SD_Global variables, String file_name)
 {
      try {
            BufferedReader in = new BufferedReader(new FileReader(file_name));
            
            variables.decrypted_field = in.readLine();
           
            in.close();
            
        }
        catch (IOException e) {
            display_message("Error in readin_decrypt(): "+e.getMessage());
            return;
        }
 }
 /************************************************************************************/
 /* create_batch_file() - This file is used to create a batch file to be executed.   */
 /************************************************************************************/   
 public String create_batch_file (SD_Global variables, Long sd_id, String command, String file_name)
 {  
     String batch_file = variables.temp_path+sd_id.toString()+"verify"+".bat";
     
//     display_message ("In create batch file.....");
     
        try {
            BufferedWriter bat_file = new BufferedWriter(new FileWriter(batch_file));
            
            bat_file.write(command);
            bat_file.write(" ");
             bat_file.write((int) '"');
            for (int f = 0; f < file_name.length(); ++f) {
               bat_file.write((int) file_name.charAt(f));
            }        
            bat_file.write((int) '"');
            
            bat_file.write(" ");
            bat_file.close();
        } catch (IOException e) {
            display_message("Error in create_batch_file(): on processing batch file "+e.getMessage());
        }

//      display_message ("Returning from create batch file.....");
     return batch_file;
 }
 /************************************************************************************/
/* compare_fields() - This function compares the value of a field in the digital   */
/*                    signature the value of the field in the change record.       */
/************************************************************************************/   
       
 public int compare_fields (String sd_form_field, String encrypted_field)
 {
   try {
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
   } catch (RuntimeException e) {
      display_message ("Error in compare_fields: "+e.getMessage());
      return 1;
   } 
 }
 
/************************************************************************************/
 /* execute_bat() - This function executes a bat file containing a security command */
 /*                    and checks for the resulting file.                           */
 /************************************************************************************/  
    
    public int execute_bat(SD_Global variables, String batch_file,String new_file,int flag)
    {
        String osName = System.getProperty("os.name" );
        
        String[] cmd = new String[3];
        
        try {
         /*   if( osName.equals( "Windows 2000" )) {}*/
                cmd[0] = "cmd.exe" ;
                cmd[1] = "/C" ;
                cmd[2] = batch_file;
            
            
            Runtime rt = Runtime.getRuntime();
            variables.logfile.write("Execing " + cmd[0] + " " + cmd[1]
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
            variables.logfile.write("ExitValue: " + exitVal);
            
            // place output messages in variable in case logging is turned on.
            
            variables.output_line = outputGobbler.output_lines();
           
            // if logging is turned on then output information into the logfile.
            
            if (variables.debugFlag == 1)
            {
                variables.logfile.write (variables.output_line);
            }
           
            
        } catch (Throwable t) {
            t.printStackTrace();
        }
        
        // Setup to delete files using standard Java function
        
        File configfile = new File(new_file);
        File batch = new File(batch_file);
        
//           try {
//                batch.delete();
//            }
//            catch (SecurityException e) {
//                display_message("Error in execute_bat(): for file "+batch.toString()+" "+e.getMessage());
//            }
       
        // If flag set do not look for existence of file from batch execution.
        
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

/************************************************************************************/
/* Sleep() - This function is no longer used.                                       */
/************************************************************************************/
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

 public int prompt_user_info (SD_Global variables, String message)
 {
     JFrame source = new JFrame();
     JLabel name=new JLabel("SD Login");
     JTextField uname=new JTextField(); 
     JLabel passwd=new JLabel("SD Password");
     JTextField pword=new JPasswordField(); 
     Object[] ob={name,uname,passwd,pword}; 
     int result = JOptionPane.showConfirmDialog(source, ob, "Service Desk Login Information", JOptionPane.OK_CANCEL_OPTION);
   
  if (result == JOptionPane.OK_OPTION) {
      variables.username= uname.getText();
      variables.password = pword.getText();
      
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
  
 /************************************************************************************/
 /* close_logfile() - This function will close the logfile                           */
 /************************************************************************************/
  public void close_logfile (SD_Global variables)
  {
      try {
          
          if (variables.debugFlag == 1)
          {
           variables.logfile.close();
          }
          
      } catch (IOException e) {
          display_message ("Error in Close_Logfile():Unable to close logfile: "+e.getMessage());
      }
  }

 /************************************************************************************/
 /* get_appl_server() - This function will get the current list of application       */
 /*                     servers that has been transmitted to the SD client.          */
 /************************************************************************************/
  public String[] get_appl_server ()
  {
      
// Get the Windows login 
      String windows_name = System.getProperty("user.name"); 
      byte[] buffer2 = null;
      String field;
      String[] server = new String[10];
      String[] split_up = new String[10];
      int num_servers = 0;

// Assemble directory and location of the server_list.txt file which contains list of application
// servers.
      
      String sd_srv_list = "C:\\Documents and Settings\\"+windows_name+"\\Application Data\\Hewlett-Packard\\OpenView\\Service Desk\\server_list.txt";    
      
      try {
                    
// Readin the list of application server which is psuedo ASCII.
                    
                File s = new File(sd_srv_list);
                
                int length = (int) s.length();
                
                FileInputStream fiss = new FileInputStream(s);
                
                buffer2 = new byte[length];
                
// the whole file is read into buffer
                
                fiss.read(buffer2);    
                
                fiss.close();
             }
               catch (IOException e) {
            display_message("Error in get_appl_server() for file : "+e.getMessage());
            }
        
            try 
            {
                StringBuffer sb1 = new StringBuffer(new String(buffer2));
                
// Convert application server list into a String.
                
               String server_list = sb1.toString();

// Parse out application server name and add to list. Application server name
// will be separated with a colon (e.g. hostname:hostname2:IP Address...)
               
              split_up = server_list.split(":");
                  
              for (int j = 0; j < split_up.length; j++) 
              {
               server[num_servers] = split_up[j];
               ++num_servers;
              }           
// Annotate the last entry in the list.
               server[num_servers] = "NO_MORE";
                }
               catch (RuntimeException e) {
            display_message("Error in get_appl_server() for file : "+e.getMessage());
            }
               
           return (server);
                
  }     
}
/************************************************************************************/
/* StreamGobbler - This class is used to extract output from MS-DOS executed        */
/*                 commands.
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

// Function used to return output from a MS-DOS executed command.
    
    public String output_lines ()
    {
        return this.output;
    }

// Function used to execute the MS-DOS command.
    public void run() {
        try {
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line=null;
            
            while ( (line = br.readLine()) != null)
            {
            /*  System.out.println(type + ">" + line);  */

// Do not include PGP -z option command in the logfile.
                
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

