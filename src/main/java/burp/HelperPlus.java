package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/*
 * source code: https://github.com/bit4woo/burp-api-common/blob/master/src/main/java/burp/HelperPlus.java
 * author: bit4woo
 * github: https://github.com/bit4woo
 * 
 * String getHeadersAsStr(boolean isRequest,byte[] requestOrResponse)
 * String getHeadersAsStr(boolean messageIsRequest,IHttpRequestResponse messageInfo) 
 * getHeaderList
 * getHeaderLine
 * getHeaderValueOf
 * 
 * addOrUpdateHeaderList
 * removeHeaderList
 * 
 * getBody
 * updateBoby #将body看做一个整体进行替换
 * 
 * shorturl
 * url
 * protocol
 * host
 * port
 * 
 * getParameters
 * addParameter --Helper中已经存在
 * byte[] addParameter(byte[] request, IParameter parameter);
 * byte[] removeParameter(byte[] request, IParameter parameter);
 * byte[] updateParameter(byte[] request, IParameter parameter);
 * Paras
 * 
 * method
 * statusCode
 * 
 * 
 */

public class HelperPlus{
	private static IExtensionHelpers helpers;
	private final static String Header_Spliter = ":";
	private final static String Header_Connector = ": ";//contains space
	private final static String Header_firstLine_Spliter = " ";

	public HelperPlus(IExtensionHelpers helpers) {
		HelperPlus.helpers = helpers;
	}
	/*
	 * 返回HTTP请求或响应的整个header头部分，与body相对应
	 */
	public String getHeadersAsStr(boolean isRequest,byte[] requestOrResponse) {
		if (requestOrResponse == null){
			return null;
		}
		int bodyOffset = -1;
		if(isRequest) {
			IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
			bodyOffset = analyzeRequest.getBodyOffset();
		}else {
			IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
			bodyOffset = analyzeResponse.getBodyOffset();
		}
		byte[] byte_header = Arrays.copyOfRange(requestOrResponse,0,bodyOffset);//not length-1
		return new String(byte_header);
	}

	/*
	 * 返回HTTP请求或响应的整个header头部分，与body相对应
	 */
	public String getHeadersAsStr(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (messageInfo == null){
			return null;
		}
		byte[] requestOrResponse = null;
		if(messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		}else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getHeadersAsStr(messageIsRequest, requestOrResponse);
	}

	/*
	 * 获取header的字符串数组，是构造burp中请求需要的格式。
	 * return headers list
	 */
	public static List<String> getHeaderList(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (null == messageInfo) {
			return new ArrayList<>();
		}
		byte[] requestOrResponse;
		if(messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		}else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getHeaderList(messageIsRequest,requestOrResponse);
	}

	/*
	 * 获取请求包或者响应包中的header List
	 */
	public static List<String> getHeaderList(boolean IsRequest,byte[] requestOrResponse) {
		if (null == requestOrResponse) {
			return new ArrayList<>();
		}
		if(IsRequest) {
			IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
			List<String> headers = analyzeRequest.getHeaders();
			return headers;
		}else {
			IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
			List<String> headers = analyzeResponse.getHeaders();
			return headers;
		}
	}

	public static List<String> addOrUpdateHeader(List<String> headers,String headerName,String headerValue) {
		for (String header:headers) {
			if (header.contains(":")) {
				try {
					String headerNameOrigin = header.split(Header_Spliter, 2)[0].trim();//这里的limit=2 可以理解成分割成2份，否则referer可能别分成3份
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						int index = headers.indexOf(header);
						headers.remove(header);
						headers.add(index, headerName+Header_Connector+headerValue);
						return headers;
					}
				}catch (Exception e) {

				}
			}
		}
		headers.add(headerName+Header_Connector+headerValue);
		return headers;
	}
	
	
	public static IHttpRequestResponse addOrUpdateHeader(boolean messageIsRequest,IHttpRequestResponse messageInfo,String headerName,String headerValue){
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		byte[] body = getBody(messageIsRequest,messageInfo);
		headers = addOrUpdateHeader(headers,headerName,headerValue);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		}else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}
	
	public static byte[] addOrUpdateHeader(boolean isRequest,byte[] requestOrResponse,String headerName,String headerValue){
		List<String> headers = getHeaderList(isRequest,requestOrResponse);
		byte[] body = getBody(isRequest,requestOrResponse);
		headers = addOrUpdateHeader(headers,headerName,headerValue);
		return helpers.buildHttpMessage(headers, body);
	}

	public static List<String> removeHeader(List<String> headers,String headerNameOrHeaderLine) {
		Iterator<String> it = headers.iterator();
		while(it.hasNext()) {
			String header = it.next();
			String headerName = header.split(Header_Spliter, 2)[0].trim();
			if (header.toLowerCase().startsWith(headerNameOrHeaderLine.toLowerCase().trim())
					&& headerNameOrHeaderLine.length() >= headerName.length()) {
				it.remove();
			}
		}
		return headers;
	}
	
	public static IHttpRequestResponse removeHeader(boolean messageIsRequest,IHttpRequestResponse messageInfo,String headerNameOrHeaderLine){
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		byte[] body = getBody(messageIsRequest,messageInfo);
		headers = removeHeader(headers,headerNameOrHeaderLine);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		}else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}
	
	/*
	 * 删除特定的header。
	 */
	public static byte[] removeHeader(boolean isRequest,byte[] requestOrResponse, String headerNameOrHeaderLine) {
		List<String> headers = getHeaderList(isRequest,requestOrResponse);
		byte[] body = getBody(isRequest,requestOrResponse);
		headers = removeHeader(headers,headerNameOrHeaderLine);
		return helpers.buildHttpMessage(headers, body);
	}
	

	/*
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public static String getHeaderLine(List<String> headers,String headerName) {
		if (null ==headers || headerName ==null) return null;
		for (String header:headers) {
			if (header.contains(":")) {
				try {
					String headerNameOrigin = header.split(Header_Spliter, 2)[0].trim();//这里的limit=2 可以理解成分割成2份，否则referer可能别分成3份
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						return header;
					}
				}catch (Exception e) {

				}
			}
		}
		return null;
	}
	
	/*
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public String getHeaderLine(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		return getHeaderLine(headers,headerName);
	}

	/*
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public String getHeaderLine(boolean messageIsRequest,byte[] requestOrResponse, String headerName) {
		List<String> headers=getHeaderList(messageIsRequest,requestOrResponse);
		return getHeaderLine(headers,headerName);
	}

	/*
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(List<String> headers,String headerName) {
		if (null ==headers || headerName ==null) return null;
		for (String header:headers) {
			if (header.contains(":")) {
				try {
					String headerNameOrigin = header.split(Header_Spliter, 2)[0].trim();//这里的limit=2 可以理解成分割成2份，否则referer可能别分成3份
					String headerValue = header.split(Header_Spliter, 2)[1].trim();
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						return headerValue;
					}
				}catch (Exception e) {

				}
			}
		}
		return null;
	}

	/*
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		return getHeaderValueOf(headers,headerName);
	}

	/*
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,byte[] requestOrResponse, String headerName) {
		List<String> headers=getHeaderList(messageIsRequest,requestOrResponse);
		return getHeaderValueOf(headers,headerName);
	}


	public static byte[] getBody(boolean isRequest,byte[] requestOrResponse) {
		if (requestOrResponse == null){
			return null;
		}
		int bodyOffset = -1;
		if(isRequest) {
			IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
			bodyOffset = analyzeRequest.getBodyOffset();
		}else {
			IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
			bodyOffset = analyzeResponse.getBodyOffset();
		}
		byte[] byte_body = Arrays.copyOfRange(requestOrResponse, bodyOffset, requestOrResponse.length);//not length-1
		//String body = new String(byte_body); //byte[] to String
		return byte_body;
	}

	public static byte[] getBody(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (messageInfo == null){
			return null;
		}
		byte[] requestOrResponse = null;
		if(messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		}else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getBody(messageIsRequest, requestOrResponse);
	}
	
	public static IHttpRequestResponse UpdateBody(boolean messageIsRequest,IHttpRequestResponse messageInfo,byte[] body){
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		}else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}
	
	public static byte[] UpdateBody(boolean isRequest,byte[] requestOrResponse,byte[] body){
		List<String> headers = getHeaderList(isRequest,requestOrResponse);
		return helpers.buildHttpMessage(headers, body);
	}

	/*
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. 
	 * the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * result example:
	 *  
	 * eg. http://bit4woo.com:80/ 包含默认端口和默认path(/)
	 */
	public URL getShortURL(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		String shortUrlString = messageInfo.getHttpService().toString();//http://www.baidu.com
		shortUrlString = formateURLString(shortUrlString);
		try {
			return new URL(shortUrlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}

	/*
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * 这个函数的返回结果转换成字符串是包含了默认端口的。
	 * http://bit4woo.com:80/test.html#123
	 */
	public final URL getFullURL(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		return analyzeRequest.getUrl();
	}


	/*
	 * to let url String contains default port(80\443) and default path(/)
	 * 
	 * from: http://bit4woo.com
	 * to  : http://bit4woo.com:80/
	 */
	public static String formateURLString(String urlString) {
		try {
			//urlString = "https://www.runoob.com";
			URL url = new URL(urlString);
			String host = url.getHost();
			int port = url.getPort();
			String path = url.getPath();

			if (port == -1) {
				String newHost = url.getHost()+":"+url.getDefaultPort();
				urlString = urlString.replace(host, newHost);
			}

			if (path.equals("")) {
				urlString = urlString+"/";
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		return urlString;
	}

	public String getHost(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getHost();
	}

	public String getProtocol(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getProtocol();
	}

	public int getPort(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getPort();
	}

	public short getStatusCode(IHttpRequestResponse messageInfo) {
		if (messageInfo == null || messageInfo.getResponse() == null) {
			return -1;
		}
		IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse());
		return analyzedResponse.getStatusCode();
	}

	public short getStatusCode(byte[] response) {
		if (response == null) {
			return -1;
		}
		try {
			IResponseInfo analyzedResponse = helpers.analyzeResponse(response);
			return analyzedResponse.getStatusCode();
		} catch (Exception e) {
			return -1;
		}
	}

	public List<IParameter> getParameters(IHttpRequestResponse messageInfo){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		return analyzeRequest.getParameters();
	}

	public List<IParameter> getParameters(byte[] request){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
		return analyzeRequest.getParameters();
	}
	
	/*
	 * 根据参数的key查找IParameter对象
	 * 需要考虑同名参数的情况
	 */
	public static List<IParameter> findParameterByKey(List<IParameter> parameters,String key){
		List<IParameter> result = new ArrayList<IParameter>();
		for (IParameter para:parameters) {
			if (para.getName().equalsIgnoreCase(key)){
				result.add(para);
			}
		}
		return result;
	}
	/*
	 * 使用burp.IExtensionHelpers.getRequestParameter(byte[], String)
	 */
	public IParameter getParameterByKey(IHttpRequestResponse messageInfo,String key){
		return helpers.getRequestParameter(messageInfo.getRequest(), key);
	}

	public IParameter getParameterByKey(byte[] request,String key){
		return helpers.getRequestParameter(request, key);
	}
	
	/*
	 * 根据参数的key和type查找IParameter对象
	 * 需要考虑同名参数的情况
	 */
	public static List<IParameter> findParameterByKeyAndType(List<IParameter> parameters,String key,byte type){
		List<IParameter> result = new ArrayList<IParameter>();
		for (IParameter para:parameters) {
			if (para.getName().equalsIgnoreCase(key) && para.getType() == type){
				result.add(para);
			}
		}
		return result;
	}

	public List<IParameter> getParameterByKeyAndType(IHttpRequestResponse messageInfo,String key,byte type){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		List<IParameter> paras = analyzeRequest.getParameters();
		return findParameterByKeyAndType(paras,key,type);
	}

	public List<IParameter> getParameterByKeyAndType(byte[] request,String key,byte type){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
		return findParameterByKeyAndType(analyzeRequest.getParameters(),key,type);
	}
	
	
	
	

	public String getMethod(IHttpRequestResponse messageInfo){
		if (messageInfo == null || messageInfo.getRequest() == null) {
			return null;
		}
		IRequestInfo analyzedRequest = helpers.analyzeRequest(messageInfo.getRequest());
		return analyzedRequest.getMethod();
	}

	public String getMethod(byte[] request){
		if (request == null) {
			return null;
		}
		try {
			IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
			return analyzedRequest.getMethod();
		} catch (Exception e) {
			return null;
		}
	}

	public String getHTTPBasicCredentials(IHttpRequestResponse messageInfo) throws Exception{
		String authHeader  = getHeaderValueOf(true, messageInfo, "Authorization").trim();
		String[] parts = authHeader.split("\\s");

		if (parts.length != 2)
			throw new Exception("Wrong number of HTTP Authorization header parts");

		if (!parts[0].equalsIgnoreCase("Basic"))
			throw new Exception("HTTP authentication must be Basic");

		return parts[1];
	}

	public static void main(String args[]) {
		List<String> headerList = new ArrayList<String>();
		headerList.add("User-Agent: sssss");
		headerList.add("Use: sssss");
		headerList.add("User: sssss");
		headerList.add("Agent: sssss");
		List<String> newHeader = removeHeader(headerList,"Use");
		System.out.println(newHeader.toString());
		newHeader = addOrUpdateHeader(headerList,"Use1","xxxx");
		System.out.println(newHeader.toString());
	}
}
