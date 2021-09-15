package burp;

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
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

/**
 * 常用操作系统操作：打开浏览器、打开文件夹、操作剪切板等
 * 
 */
public class SytemUtils {

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

	public static boolean isWindows() {
		String OS_NAME = System.getProperty("os.name").toLowerCase();
		if (OS_NAME.contains("windows")) {
			return true;
		} else {
			return false;
		}
	}
	
	public static boolean isWindows10() {
		String OS_NAME = System.getProperty("os.name").toLowerCase();
		if (OS_NAME.equalsIgnoreCase("windows 10")) {
			return true;
		}
		return false;
	}

	public static boolean isMac(){
		String os = System.getProperty("os.name").toLowerCase();
		return (os.indexOf( "mac" ) >= 0); 
	}

	/**
	 * //linux or unix
	 * @return
	 */
	public static boolean isUnix(){
		String os = System.getProperty("os.name").toLowerCase();
		return (os.indexOf( "nix") >=0 || os.indexOf( "nux") >=0);
	}

	/**
	 * 将文本写入系统剪切板
	 * @param text
	 */
	public static void writeToClipboard(String text) {
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection selection = new StringSelection(text);
		clipboard.setContents(selection, null);
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

	/**
	 * 判断某个文件是否在环境变量中
	 */
	@Deprecated
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
	
	public static void editWithVSCode(String filepath) {
		// /Applications/Visual Studio Code.app/Contents/MacOS/Electron
		if (filepath.contains(" ")){
			filepath = "\""+filepath+"\"";
		}
		if (isMac()) {
			try {
				String[] cmdArray = new String[] {"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",filepath};
				Runtime.getRuntime().exec(cmdArray);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if (isWindows()) {
			try {
				String[] cmdArray = new String[] {"code.cmd",filepath};
				Runtime.getRuntime().exec(cmdArray);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	

	public static void main(String args[]) {
	}
}

