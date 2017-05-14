import java.io.*;
import java.io.IOException;
import java.lang.*;
import java.util.*;
import java.util.zip.*;
import javax.swing.*;
import com.hp.itsm.api.*;
import com.hp.itsm.api.interfaces.*;
import com.hp.ifc.util.ApiDateUtils;

class SD_Global {
 
// Definition of global variables
    public String temp_path = "c:\\program files\\service desk integration\\sd encryption\\";
    public String sign_file = null;
    public ApiSDSession session;
    public String command_info = null;
    public String entry_separator = ";;";
    public String field_separator = "::";
    public String config_field_separator = ";";
    public String username = null;
    public String password = null;
    public String output_line = null;
    public int debugFlag = 0;
    public String log_file = null;
    public BufferedWriter logfile;
    public String decrypted_field = null;
    public int no_sigs = 0;
    public String stars = "******************************************************";
    public int signer_or_viewer = 0;
 }