/*
 * SD_testing.java
 *
 * Created on March 14, 2003, 10:07 AM
 */
import javax.swing.*;

public class SD_program {
    
    /** Creates a new instance of SD_testing */
    public SD_program() {
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        SD_Common function = new SD_Common ();
        SD_Global variables = new SD_Global();
        SD_Security_System sd_security = new SD_Security_System();
        
 // Ensure correct number of arguments. Otherwise, abort and print message   
        
         if (args.length != 3)
          {
            function.display_message ("Incorrect number of agruments passed\nFor example:\n       SD_Encryption <Security Name> <SD Record ID> <function>\n");
            System.exit(1);
         }
        
          String security = args[0];
          Long id = new Long (args[1]);
          String command = args[2];
          
          String[] servers = function.get_appl_server();
          
          try {
           SD_Form sd_form1 = new SD_Form();
          }catch (RuntimeException e) {
          function.display_message (e.getMessage());
            }
           
          
           try {
          SD_Form sd_form = new SD_Form();
           

// Get the SD Encryption configuration information and the change record information.
          
        if (sd_form.get_SD_Fields(variables,function,sd_security,security,servers,id,1) != 0)
        {
            System.exit(1);
        }

// Determine if the change record is in the appropriate approval state
          
        if (sd_form.is_form_approved (function) != 0)
        {
            function.display_message ("Error: Form must be in approved state to perform function");
            System.exit(2);
        }

// Determine if the user is authorized to use the security system.
          
        if (sd_security.authorizes_user(variables,function,sd_security, sd_form) != 0)
         {
            System.exit(3);
         }
        SD_Signature sd_signature = new SD_Signature();
        
// Determine if this is "Sign Form" option    
        if (command.compareTo("encrypt") == 0)
        {
           sd_signature.create_signature(variables,function,sd_security,sd_form);
        }
        
// Determine if this is "Verify Signature" option
          
        if (command.compareTo("decrypt") == 0)
        {
          sd_signature.decrypts_data(variables,function,sd_security,sd_form,"decrypt");
        }

// Determine if this is "Display Signature" option
           
        if (command.compareTo("display") == 0)
        {
          sd_signature.decrypts_data(variables,function,sd_security,sd_form,"DISPLAY ONLY");
        }
// Determine if this is "Show Signers" option
           
        if (command.compareTo("signers") == 0)
        {
          sd_signature.decrypts_data(variables,function,sd_security,sd_form,"SIGNERS ONLY");
        }
      
// Determine if this is "Delete Signature" option
            
        if (command.compareTo("delete") == 0)
        {
          sd_signature.delete_signature(variables,function,sd_form,"delete");
        }
     } catch (RuntimeException e) {
          function.display_message (e.getMessage());
      }
          function.close_logfile(variables);
          System.exit(0);
    }
    
    
}
