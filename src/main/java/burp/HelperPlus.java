package burp;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
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
	/**
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

	/**
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

	/**
	 * 获取header的字符串数组，是构造burp中请求需要的格式。
	 * return headers list
	 */
	public List<String> getHeaderList(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
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

	/**
	 * 获取请求包或者响应包中的header List
	 */
	public List<String> getHeaderList(boolean IsRequest,byte[] requestOrResponse) {
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

	/**
	 * 新增或更新header
	 */
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

	/**
	 * 新增或更新header
	 */
	public IHttpRequestResponse addOrUpdateHeader(boolean messageIsRequest,IHttpRequestResponse messageInfo,String headerName,String headerValue){
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

	/**
	 * 新增或更新header
	 */
	public byte[] addOrUpdateHeader(boolean isRequest,byte[] requestOrResponse,String headerName,String headerValue){
		List<String> headers = getHeaderList(isRequest,requestOrResponse);
		byte[] body = getBody(isRequest,requestOrResponse);
		headers = addOrUpdateHeader(headers,headerName,headerValue);
		return helpers.buildHttpMessage(headers, body);
	}

	/**
	 * 删除header
	 */
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

	/**
	 * 删除header
	 */
	public IHttpRequestResponse removeHeader(boolean messageIsRequest,IHttpRequestResponse messageInfo,String headerNameOrHeaderLine){
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

	/**
	 * 删除特定的header。
	 */
	public byte[] removeHeader(boolean isRequest,byte[] requestOrResponse, String headerNameOrHeaderLine) {
		List<String> headers = getHeaderList(isRequest,requestOrResponse);
		byte[] body = getBody(isRequest,requestOrResponse);
		headers = removeHeader(headers,headerNameOrHeaderLine);
		return helpers.buildHttpMessage(headers, body);
	}


	/**
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

	/**
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public String getHeaderLine(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		return getHeaderLine(headers,headerName);
	}

	/**
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public String getHeaderLine(boolean messageIsRequest,byte[] requestOrResponse, String headerName) {
		List<String> headers=getHeaderList(messageIsRequest,requestOrResponse);
		return getHeaderLine(headers,headerName);
	}

	/**
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public static String getHeaderValueOf(List<String> headers,String headerName) {
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

	/**
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		return getHeaderValueOf(headers,headerName);
	}

	/**
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,byte[] requestOrResponse, String headerName) {
		List<String> headers=getHeaderList(messageIsRequest,requestOrResponse);
		return getHeaderValueOf(headers,headerName);
	}

	/**
	 * 获取数据包的body
	 */
	public static byte[] getBody(boolean isRequest,byte[] requestOrResponse) {
		if (requestOrResponse == null){
			return null;
		}
		int bodyOffset = -1;

		if (helpers != null) {
			if(isRequest) {
				IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
				bodyOffset = analyzeRequest.getBodyOffset();
			}else {
				IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
				bodyOffset = analyzeResponse.getBodyOffset();
			}
		}else {
			bodyOffset = Common.BytesIndexOf("\r\n\r\n".getBytes(), requestOrResponse);
			bodyOffset = bodyOffset+4;
		}
		byte[] byte_body = Arrays.copyOfRange(requestOrResponse, bodyOffset, requestOrResponse.length);//not length-1
		//String body = new String(byte_body); //byte[] to String
		return byte_body;
	}

	/**
	 * 获取数据包的body
	 */
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

	/**
	 * 更新数据包的body
	 */
	public IHttpRequestResponse UpdateBody(boolean messageIsRequest,IHttpRequestResponse messageInfo,byte[] body){
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		}else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}

	/**
	 * 更新数据包的body
	 */
	public byte[] UpdateBody(boolean isRequest,byte[] requestOrResponse,byte[] body){
		List<String> headers = getHeaderList(isRequest,requestOrResponse);
		return helpers.buildHttpMessage(headers, body);
	}

	/**
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. 
	 * the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * result example:
	 *  
	 * eg. http://bit4woo.com/ 不包含默认端口；包含默认path(/)
	 * 是符合通常浏览器中使用格式的
	 */
	public static URL getShortURL(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		IHttpService service = messageInfo.getHttpService();
		//String shortUrlString = messageInfo.getHttpService().toString();//http://www.baidu.com
		//新版本burp中，API发生了变化，返回结果是这种burp.Ze6r@7f06cf44/
		
		String shortUrlString = getShortURL(service);
		try {
			return new URL(shortUrlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static String getShortURL(IHttpService service){	
		//String shortUrlString = messageInfo.getHttpService().toString();//http://www.baidu.com
		//新版本burp中，API发生了变化，返回结果是这种burp.Ze6r@7f06cf44/
		if (service ==null){
			return null;
		}
		String shortUrlString = service.getProtocol()+"://"+service.getHost()+":"+service.getPort()+"/";
		return shortUrlString;
	}

	/**
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. 
	 * the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * result example:
	 *  
	 * eg. http://bit4woo.com:80/ 包含默认端口和默认path(/) 
	 * @param messageInfo
	 * @return
	 */
	public static URL getShortURLWithDefaultPort(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		IHttpService service = messageInfo.getHttpService();
		//String shortUrlString = messageInfo.getHttpService().toString();//http://www.baidu.com
		//新版本burp中，API发生了变化，返回结果是这种burp.Ze6r@7f06cf44/
		String shortUrlString = getShortURL(service);
		shortUrlString = formateURLString(shortUrlString);
		try {
			return new URL(shortUrlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}


	/**
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * 不包含默认端口的URL格式，符合通常浏览器中的格式
	 * http://bit4woo.com/test.html#123
	 */
	public final URL getFullURL(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		String tmpurl =  analyzeRequest.getUrl().toString();
		tmpurl = removeDefaultPort(tmpurl);
		try {
			URL url = new URL(tmpurl);
			return url;
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * 这个函数的返回结果转换成字符串是包含了默认端口的。
	 * http://bit4woo.com:80/test.html#123
	 */
	public final URL getFullURLWithDefaultPort(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		return analyzeRequest.getUrl();
	}


	/**
	 * to let url String contains default port(80\443) and default path(/)
	 * 
	 * from: http://bit4woo.com
	 * to  : http://bit4woo.com:80/
	 */
	@Deprecated
	public static String formateURLString(String urlString) {
		return addDefaultPort(urlString);
	}

	/**
	 * 对URL添加默认端口。
	 * burp中获取到的URL是包含默认端口的，但是平常浏览器中的URL格式都是不包含默认端口的。
	 * 应该尽量和平常使用习惯保存一致！所以尽量避免使用该函数。
	 * @param urlString
	 * @return
	 */
	public static String addDefaultPort(String urlString) {
		try {
			//urlString = "https://www.runoob.com";
			URL url = new URL(urlString);
			String host = url.getHost();
			int port = url.getPort();
			String path = url.getPath();

			if (port == -1) {
				String newHost = url.getHost()+":"+url.getDefaultPort();
				urlString = urlString.replaceFirst(host, newHost);
			}

			if (path.equals("")) {
				urlString = urlString+"/";
			}
			return new URL(urlString).toString();
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return urlString;
		}
	}
	
    // 添加默认端口的方法
    public static String getUrlWithDefaultPort(String url) {
        try {
            URI uri = new URI(url);

            // 如果URL中没有明确指定端口，且协议为http，则添加默认端口80
            if (uri.getPort() == -1 ) {
            	if ("http".equalsIgnoreCase(uri.getScheme())) {
            		return new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), 80, uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
            	}
            	if ("https".equalsIgnoreCase(uri.getScheme())) {
            		return new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), 443, uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
            	}
            }
            // 其他情况直接返回原始URL
            return url;
        } catch (URISyntaxException e) {
            // 处理URI语法错误
            e.printStackTrace();
            return url;
        }
    }

	/**
	 * remove default port(80\443) from the url
	 * 这个格式和我们平常浏览器中看到的格式才是一致的，符合使用习惯
	 * 
	 * from: http://bit4woo.com:80/
	 * to  : http://bit4woo.com/
	 */
	public static String removeDefaultPort(String urlString) {
		try {
			//urlString = "https://www.runoob.com";
			URL url = new URL(urlString);
			String protocol = url.getProtocol();
			String host = url.getHost();
			int port = url.getPort();//不包含端口时返回-1
			String path = url.getPath();

			if ((port == 80 && protocol.equalsIgnoreCase("http"))
					|| (port == 443 && protocol.equalsIgnoreCase("https"))) {
				String oldHost = url.getHost()+":"+url.getPort();
				urlString = urlString.replaceFirst(oldHost, host);
			}

			if (path.equals("")) {
				urlString = urlString+"/";
			}
			return new URL(urlString).toString();
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return urlString;
		}
	}

	public static String getHost(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getHost();
	}

	public static String getProtocol(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getProtocol();
	}

	public static int getPort(IHttpRequestResponse messageInfo) {
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


	/**
	 * 使用burp.IExtensionHelpers.getRequestParameter(byte[], String),未考虑同名参数的情况！
	 */
	public IParameter getParameterByKey(IHttpRequestResponse messageInfo,String key){
		return helpers.getRequestParameter(messageInfo.getRequest(), key);
	}

	public IParameter getParameterByKey(byte[] request,String key){
		return helpers.getRequestParameter(request, key);
	}


	/**
	 * 根据参数的key查找IParameter对象，考虑了同名函数的情况，但这种情况很少，几乎用不上。
	 * 尽量不要使用这个函数
	 */
	@Deprecated
	public static List<IParameter> findParametersByKey(List<IParameter> parameters,String key){
		List<IParameter> result = new ArrayList<IParameter>();
		for (IParameter para:parameters) {
			if (para.getName().equalsIgnoreCase(key)){
				result.add(para);
			}
		}
		return result;
	}

	/**
	 * 根据参数的key和type查找IParameter对象
	 * 考虑了同名函数的情况，但这种情况很少，几乎用不上
	 * 尽量不要使用这个函数
	 */
	@Deprecated
	public static List<IParameter> findParametersByKeyAndType(List<IParameter> parameters,String key,byte type){
		List<IParameter> result = new ArrayList<IParameter>();
		for (IParameter para:parameters) {
			if (para.getName().equalsIgnoreCase(key) && para.getType() == type){
				result.add(para);
			}
		}
		return result;
	}

	/**
	 *  考虑了同名函数的情况，但这种情况很少，几乎用不上
	 *  尽量不要使用这个函数
	 */
	@Deprecated
	public List<IParameter> getParametersByKeyAndType(IHttpRequestResponse messageInfo,String key,byte type){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		List<IParameter> paras = analyzeRequest.getParameters();
		return findParametersByKeyAndType(paras,key,type);
	}

	/**
	 *  考虑了同名函数的情况，但这种情况很少，几乎用不上
	 *  尽量不要使用这个函数
	 */
	@Deprecated
	public List<IParameter> getParametersByKeyAndType(byte[] request,String key,byte type){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
		return findParametersByKeyAndType(analyzeRequest.getParameters(),key,type);
	}


	public IHttpRequestResponse addOrUpdateParameter(IHttpRequestResponse messageInfo,IParameter para){
		byte[] request = messageInfo.getRequest();
		request = addOrUpdateParameter(request, para);
		messageInfo.setRequest(request);
		return messageInfo;
	}

	public byte[] addOrUpdateParameter(byte[] request,IParameter para){
		IParameter existPara = helpers.getRequestParameter(request, para.getName());
		if (null != existPara) {
			request = helpers.removeParameter(request, existPara);
		}
		request = helpers.addParameter(request, para);
		return request;
	}

	public IHttpRequestResponse removeParameter(IHttpRequestResponse messageInfo, IParameter parameter) {
		byte[] request = messageInfo.getRequest();
		request = helpers.removeParameter(request, parameter);
		messageInfo.setRequest(request);
		return messageInfo;
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

	private static void test1() {
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
	private static void test2() {
		String url = "http://www.baidu.com";
		String url2 = "https://www.baidu.com:443";
		System.out.println(addDefaultPort(url));
		System.out.println(removeDefaultPort(url2));
		System.out.println(removeDefaultPort(url));
		System.out.println(addDefaultPort(url));
	}
	public static void main(String args[]) {
		test2();
	}
}
