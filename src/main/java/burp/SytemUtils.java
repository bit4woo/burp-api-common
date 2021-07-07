package burp;

import java.awt.Component;
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JOptionPane;
import javax.swing.JTextArea;

/*
 * 常用操作系统操作：打开浏览器、打开文件夹、操作剪切板等
 * 
 */
public class SytemUtils {

	public static String set2string(Set<?> set){
		Iterator iter = set.iterator();
		StringBuilder result = new StringBuilder();
		while(iter.hasNext())
		{
			//System.out.println(iter.next());  		
			result.append(iter.next()).append("\n");
		}
		return result.toString();
	}

	public static boolean uselessExtension(String urlpath) {
		Set<String> extendset = new HashSet<String>();
		extendset.add(".gif");
		extendset.add(".jpg");
		extendset.add(".png");
		extendset.add(".css");//gif,jpg,png,css,woff
		extendset.add(".woff");
		Iterator<String> iter = extendset.iterator();
		while (iter.hasNext()) {
			if(urlpath.endsWith(iter.next().toString())) {//if no next(), this loop will not break out
				return true;
			}
		}
		return false;
	}

	public static String getNowTimeString() {
		SimpleDateFormat simpleDateFormat = 
				new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
		return simpleDateFormat.format(new Date());
	}

	public static void browserOpen(Object url,String browser) throws Exception{
		String urlString = null;
		URI uri = null;
		if (url instanceof String) {
			urlString = (String) url;
			uri = new URI((String)url);
		}else if (url instanceof URL) {
			uri = ((URL)url).toURI();
			urlString = url.toString();
		}
		if(browser == null ||browser.equalsIgnoreCase("default") || browser.equalsIgnoreCase("")) {
			//whether null must be the first
			Desktop desktop = Desktop.getDesktop();
			if(Desktop.isDesktopSupported()&&desktop.isSupported(Desktop.Action.BROWSE)){
				desktop.browse(uri);
			}
		}else {
			String[] cmdArray = new String[] {browser,urlString};

			//runtime.exec(browser+" "+urlString);//当命令中有空格时会有问题
			Runtime.getRuntime().exec(cmdArray);
		}
	}

	public static List<Integer> Port_prompt(Component prompt, String str){
		String defaultPorts = "8080,8000,8443";
		String user_input = JOptionPane.showInputDialog(prompt, str,defaultPorts);
		if (null == user_input || user_input.trim().equals("")) return  null; 
		List<Integer> portList = new ArrayList<Integer>();
		for (String port: user_input.trim().split(",")) {
			int portint = Integer.parseInt(port);
			portList.add(portint);
		}
		return portList;
	}

	public static boolean isWindows() {
		String OS_NAME = System.getProperties().getProperty("os.name").toLowerCase();
		if (OS_NAME.contains("windows")) {
			return true;
		} else {
			return false;
		}
	}

	public static void writeToClipboard(String text) {
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection selection = new StringSelection(text);
		clipboard.setContents(selection, null);
	}

	public static List<String> getLinesFromTextArea(JTextArea textarea){
		//user input maybe use "\n" in windows, so the System.lineSeparator() not always works fine!
		String[] lines = textarea.getText().replaceAll("\r\n", "\n").split("\n");
		List<String> result = new ArrayList<String>();
		for(String line: lines) {
			line = line.trim();
			if (line!="") {
				result.add(line.trim());
			}
		}
		return result;
	}

	public static void openPoCFile(String filepath) {
		// /Applications/Visual Studio Code.app/Contents/MacOS/Electron
		if (isInEnvironmentPath("code.cmd")) {//windows下的vscode
			try {
				String[] cmdArray = new String[] {"code.cmd","\""+filepath+"\""};
				Runtime.getRuntime().exec(cmdArray);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}else if (isInEnvironmentPath("idle.bat")){
			try {
				String[] cmdArray = new String[] {"idle.bat","\""+filepath+"\""};
				Runtime.getRuntime().exec(cmdArray);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}else {
			try {
				String[] cmdArray = new String[] {"/Applications/Visual Studio Code.app/Contents/MacOS/Electron","\""+filepath+"\""};
				Runtime.getRuntime().exec(cmdArray);
			} catch (IOException e) {
				e.printStackTrace();
			}
			try {
				//JOptionPane.showMessageDialog(null,"Not found editor(code.exe idle.bat) in environment.");
				File file = new File(filepath);
				OpenFolder(file.getParent());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	/*
	 * parserPath --- python.exe java.exe ....
	 * executerPath --- sqlmap.py nmap.exe ....
	 * parameters ---- -v -A -r xxx.file .....
	 */
	public static String genCmd(String parserPath,String executerPath, String parameter) {
		StringBuilder command = new StringBuilder();

		if (parserPath != null){
			if (parserPath.contains(" ")) {
				parserPath = "\""+parserPath+"\"";//如果路径中包含空格，需要引号
			}
			command.append(parserPath);
			command.append(" ");
		}

		if ((executerPath != null && new File(executerPath).exists() && new File(executerPath).isFile())
				|| isInEnvironmentPath(executerPath)){

			if (executerPath.contains(" ")) {
				executerPath = "\""+executerPath+"\"";//如果路径中包含空格，需要引号
			}

			command.append(executerPath);
			command.append(" ");
		}

		if (parameter != null && !parameter.equals("")) {
			command.append(parameter);
		}
		command.append(System.lineSeparator());
		return command.toString();
	}

	/*
	 * 判断某个文件是否在环境变量中
	 */
	public static boolean isInEnvironmentPath(String filename) {
		if (filename == null) {
			return false;
		}
		Map<String, String> values = System.getenv();
		String pathvalue = values.get("PATH");
		if (pathvalue == null) {
			pathvalue = values.get("path");
		}
		if (pathvalue == null) {
			pathvalue = values.get("Path");
		}
		//		System.out.println(pathvalue);
		String[] items = pathvalue.split(";");
		for (String item:items) {
			File tmpPath = new File(item);
			if (tmpPath.isDirectory()) {
				//				System.out.println(Arrays.asList(tmpPath.listFiles()));
				File fullpath = new File(item,filename);
				if (Arrays.asList(tmpPath.listFiles()).contains(fullpath)) {
					return true;
				}else {
					continue;
				}
			}
		}
		return false;
	}


	public static boolean isWindows10() {
		String OS_NAME = System.getProperties().getProperty("os.name").toLowerCase();
		if (OS_NAME.equalsIgnoreCase("windows 10")) {
			return true;
		}
		return false;
	}

	public static boolean isMac(){
		String os = System.getProperty("os.name").toLowerCase();
		//Mac
		return (os.indexOf( "mac" ) >= 0); 
	}

	public static boolean isUnix(){
		String os = System.getProperty("os.name").toLowerCase();
		//linux or unix
		return (os.indexOf( "nix") >=0 || os.indexOf( "nux") >=0);
	}


	public static void OpenFolder(String path) throws IOException {
		String program = null;
		if (isWindows()){
			program = "explorer.exe";
		}else if(isMac()){
			program = "open";
		}else {
			program = "nautilus";
		}
		if ((path.startsWith("\"") && path.endsWith("\"")) || (path.startsWith("'") && path.endsWith("'"))){

		}else if (path.contains(" ")){
			path = "\""+path+"\"";
		}
		String[] cmdArray = new String[] {program,path};
		Runtime.getRuntime().exec(cmdArray);
	}
	
	public static void byte2File(byte[] buf, String filePath, String fileName)
	{
		BufferedOutputStream bos = null;
		FileOutputStream fos = null;
		File file = null;
		try
		{
			File dir = new File(filePath);
			if (!dir.exists() && dir.isDirectory())
			{
				dir.mkdirs();
			}
			file = new File(filePath + File.separator + fileName);
			fos = new FileOutputStream(file);
			bos = new BufferedOutputStream(fos);
			bos.write(buf);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			if (bos != null)
			{
				try
				{
					bos.close();
				}
				catch (IOException e)
				{
					e.printStackTrace();
				}
			}
			if (fos != null)
			{
				try
				{
					fos.close();
				}
				catch (IOException e)
				{
					e.printStackTrace();
				}
			}
		}
	}
	
	public static byte[] File2byte(String filePath)
	{
		byte[] buffer = null;
		try
		{
			File file = new File(filePath);
			FileInputStream fis = new FileInputStream(file);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] b = new byte[1024];
			int n;
			while ((n = fis.read(b)) != -1)
			{
				bos.write(b, 0, n);
			}
			fis.close();
			bos.close();
			buffer = bos.toByteArray();
		}
		catch (FileNotFoundException e)
		{
			e.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		return buffer;
	}
	

	public static void main(String args[]) {
		openPoCFile("D:\\github\\POC-T\\script\\activemq-upload.py");
	}
}

