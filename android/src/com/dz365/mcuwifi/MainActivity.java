package com.dz365.mcuwifi;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.ArrayList;

import java.util.List;

import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Vibrator;
import android.app.Activity;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.view.Menu;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

class public_info {
	static byte buf[] = null;
	static byte buf_length;
	static boolean need_send_cmd;
	static boolean recv_thread_exit;
	static boolean info_thread_exit;
}


class clientInfoThread extends Thread {
	Socket socket = null;
	Handler handler;
	String host = "10.10.100.254";  // wifi 模块默认：tcp server 10.10.100.254    端口8899
	int port = 8899;	
	boolean need_send_cmd = false;
	
	DataInputStream dis = null;
	DataOutputStream dos = null;
	
	public clientInfoThread(Handler handler) {				
		this.handler = handler;				
	}
	
	public void run() {
		try {		  
		  byte readBuffer[] = new byte[64];		  
		  
  	      try {
		    //socket = new Socket(host,port);
  	    	socket = new Socket();
  	    	
  	    	SocketAddress socketAddress = new InetSocketAddress(host,port);
  	    	//创建一个给定的端口号端口和主机主机插座端点。主机名是试图解决，不能为空。为有效的端口数的范围是0和65535之间的包容性。
  	    	socket.connect(socketAddress,2000);
  	    	//将套接字连接到远程主机地址与给定的指定的超时SocketAddress remoteAddr的指定端口。连接方法将阻塞直到连接被建立了，或者发生了一个错误。
		    socket.setSoTimeout(300);
		    //在此套接字读取超时设置毫秒。使用0的没有超时。生效，此选项必须设置在被阻塞的方法。
		    socket.setTcpNoDelay(true);
		    //是否立即发送此字节
		  
		    dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		    dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
		    
		    
		    //返回一个布尔值，指示是否当前线程（currentthread()）有一个未决的中断请求（TRUE）或不（假）。它还具有清旗的副作用。
		    while (!Thread.interrupted()) {
		      //Thread.sleep(1000);	
		      if (public_info.need_send_cmd) {
		    	  public_info.need_send_cmd = false;
		    	  dos.write(public_info.buf, 0, public_info.buf_length);//从字节数组写入计数字节缓冲区起始位置到目标流。
			      dos.flush();//刷新流以确保所有挂起的数据发送到目标流。这也将实现目标流。
		      }
		      int count = 0;
			  try {
					count = dis.read(readBuffer);//相当于读（缓冲区，0，缓冲区的长度。）
			   } catch (IOException e) {
					continue;
			   }
			   if (count < 1)
					continue;
				Message msg = new Message();
				msg.what = 0x1234;
				//用户定义的消息代码，以便收件人可以确定这个消息的信息。每个处理器都有其自己的名称空间的信息码，所以你不需要担心你与其他程序冲突。
				msg.obj = readBuffer;
				//任意一个对象发送给收件人。当使用Messenger发送讯息的过程，这只能是非空，如果它包含一个打包的一个框架类（而不是一个由应用程序实现）。其他数据传输使用setData。
				handler.sendMessage(msg);
				//发送到消息队列
			
		    }
		    
		    
		    }finally {
		      if (dos != null)	  
			    dos.close();
			  if (dis != null)
			    dis.close();
			  if (socket != null)
			    socket.close();
			  public_info.info_thread_exit = true;
		    }					  		 			  		  
		} catch (Exception e) {
			e.printStackTrace();
			
			Message msg = new Message();
			msg.what = 0x1235;
			msg.obj = e.getMessage();
			handler.sendMessage(msg);
		}
	}

}

public class MainActivity extends Activity {
	Button btnSearchWIFI;
	Button connectBtn;
	Button ledonBtn,ledoffBtn;
	Button jdqonBtn,jdqoffBtn;
	Button btnSend;
	
	EditText edtInfo;
	
	TextView tvInfo;
	WifiManager wifi;
	boolean changed_wifi;
	boolean connected_server;
	String old_ssid;
	Vibrator vib;                         //手机系统震动 对象  
	int old_id;
	String current_ssid;
	Handler netMessageHandle;
	clientInfoThread client_info_thread;
	//Wifi密码类型     WEP   WPA：Wi-Fi网络保护访问，无效和没密码
	public enum WifiCipherType  
    {  
      WIFICIPHER_WEP,WIFICIPHER_WPA, WIFICIPHER_NOPASS, WIFICIPHER_INVALID  
    }  
	
	

	public void connect_server() {
		public_info.buf_length = 8;
		public_info.buf = new byte[public_info.buf_length];
		public_info.need_send_cmd = false;
		public_info.recv_thread_exit = false;
		public_info.info_thread_exit = false;
				
		// 判断  wifi 是否已经连接
		ConnectivityManager connManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
		
		while (true) {
			//介绍了网络接口的状态//返回一个特定的网络连接状态的信息类型。
		  NetworkInfo mWifi = connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);  
		  if (mWifi == null)
			  continue;
		  //指示是否存在网络连接，可以建立连接和数据传递。
		  if (mWifi.isConnected()) {
			  break;
		  }
		}
		
		client_info_thread = new clientInfoThread(netMessageHandle);
		client_info_thread.start();
		
		set_btn_status(true);                                //允许界面按钮操作
	}
	
	public void disconnect_server() {
		client_info_thread.interrupt();	
		//客户端信息的线程
	}
	
	public void set_btn_status(boolean status)
	{
		Button ledonBtn = (Button)findViewById(R.id.ledonBtn);
		ledonBtn.setEnabled(status);		
		Button ledoffBtn = (Button)findViewById(R.id.ledoffBtn);
		ledoffBtn.setEnabled(status);
		Button jdqonBtn = (Button)findViewById(R.id.jdqonBtn);
		jdqonBtn.setEnabled(status);
		Button jdqoffBtn = (Button)findViewById(R.id.jdqoffBtn);
		jdqoffBtn.setEnabled(status);
		Button btnSend = (Button)findViewById(R.id.btnSend);
		btnSend.setEnabled(status);
	}
	
	protected void onDestroy() {
		super.onDestroy();		
		try {
			//unregisterReceiver(null);
		  disconnect_server();	
		  if (changed_wifi) {                //恢复之前的wifi网络
			  WifiConfiguration tempConfig = IsExists(old_ssid);//一个类代表一个配置Wi-Fi网络，包括安全配置
			  if (tempConfig != null) {
				 wifi.enableNetwork(tempConfig.networkId, true); 
				 //允许先前配置的网络是与。如果禁用其他人是真的，那么所有其他配置的网络被禁用，并试图连接到所选的网络启动。这可能会导致状态改变事件的异步发送。
			  }
		  }		  
		  Toast.makeText(getApplicationContext(), "Wi-Fi测试应用程序退出", Toast.LENGTH_LONG).show();  //提示信息
		}catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	 private WifiConfiguration CreateWifiInfo(String SSID, String Password, WifiCipherType Type)   {  
	         WifiConfiguration config = new WifiConfiguration();    
	         //认证协议的支持这个配置集。看到的authalgorithm值的说明。缺省为自动选择。
	        // 组密码支持这个配置集。看到的groupcipher值的说明。缺省为CCMP TKIP wep104 wep40。
	         //此配置的支持WPA两两密码设定。看到的pairwisecipher值的说明。缺省为CCMP TKIP。
	         //安全协议支持此配置集。看到的值描述协议。缺省为水渍险RSN。
	         //清除所有位在这bitset。该方法不改变的能力。使用明确的如果你想重用这bitset对象的相同的能力，但创建一个新的bitset如果你想有潜在回收内存。
	         config.allowedAuthAlgorithms.clear();  
	         config.allowedGroupCiphers.clear();  
	         config.allowedKeyManagement.clear();  
	         config.allowedPairwiseCiphers.clear();  
	         config.allowedProtocols.clear();  
	         //网络的SSID。可以是一个ASCII字符串，必须用双引号括起来（例如，“mynetwork”，或一个字符串的十六进制数字，而不是用引号括起来（例如，01a243f405）。
	         config.SSID = "\"" + SSID + "\"";  
	         //config.hiddenSSID = true;
	         //config.status = WifiConfiguration.Status.ENABLED;
	         
	         if(Type == WifiCipherType.WIFICIPHER_NOPASS)  
	         {  
	              //高达四的WEP密钥。一个ASCII字符串用双引号（例如，“ABCDEF”或一个字符串的十六进制数字（例如，0102030405）。
	        	  config.wepKeys[0] = "\""+"\""; 
	        	  //密钥管理协议支持此配置集。看到的keymgmt值的说明。缺省为WPA-PSK wpa-eap。//公认的密钥管理方案。
	              config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);  
	              //默认的密钥索引，范围从0到3。
	              config.wepTxKeyIndex = 0;  	              
	              
	        }  
	         else if(Type == WifiCipherType.WIFICIPHER_WEP)  
	        {  
	        	 //预共享密钥使用预共享密钥。当这个键读取值，实际的密钥是不退还的，只是一个“*”如果键是有价值的，或空字符串，否则。
	             config.preSharedKey = "\""+Password+"\"";   
	             //这是一个网络广播其SSID的，不安的SSID，所以必须特异性探针用于扫描的请求。
	             config.hiddenSSID = true;
	             //认证协议的支持这个配置集。看到的authalgorithm值的说明。缺省为自动选择。共享密钥认证（需要静态WEP密钥）
	             config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED); 
	             //组密码支持这个配置集。看到的groupcipher值的说明。缺省为CCMP TKIP wep104 wep40。AES和CBC-MAC [ RFC 3610计数器模式，IEEE 802.11i / d7.0 ]
	             config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP); 
	             //临时密钥完整性协议[ IEEE 802.11i / d7.0 ]
	             config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
	             //WEP（有线等效保密wep40 =）与40位密钥（原802.11）
	             config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40); 
	             //wep104 = WEP（有线等效保密）的104位密钥
	             config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);  
	             //WPA是没有用的；纯文本或静态WEP可以用。
	             config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE); 
	             
	             config.wepTxKeyIndex = 0;  
	        }  
	         else if(Type == WifiCipherType.WIFICIPHER_WPA)  
	        {  
	             config.preSharedKey = "\""+Password+"\"";  
	             config.hiddenSSID = true;  
	             //开放系统认证（对WPA/WPA2要求）
	             config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN); 
	             //临时密钥完整性协议[ IEEE 802.11i / d7.0 ]
	             config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
	             //密钥管理协议的一组支持这种配置。keymgmt描述的是企业的价值观。WPA WPA - PSK）的默认的认证。WPA预共享密钥（需要presharedkey被指定）。
	             config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);                          
	             //在这种ciphers WPA集是支持这种配置。pairwisecipher描述的是企业的价值观。默认值对TKIP的CCMP。公认的成对的密码WPA
	             config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);                     
	             //安全协议支持此配置集。公认的安全协议。
	             config.allowedProtocols.set(WifiConfiguration.Protocol.WPA);                       
	             //config.status = WifiConfiguration.Status.ENABLED;
	             config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
	             //此配置的支持WPA两两密码设定。看到的pairwisecipher值的说明。缺省为CCMP TKIP。
	             config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
	        }  
	      else  {  
	    	  return null;  
	      }  
	      return config;  
	}  
	 
	 private WifiConfiguration IsExists(String SSID) {      //查找 ssid 号的配置网络//exists存在
	       List<WifiConfiguration> existingConfigs = wifi.getConfiguredNetworks();  //获取 配置的网络
	       for (WifiConfiguration existingConfig : existingConfigs)   {  
	          //比较指定对象的字符串，返回true，如果这是平等的。对象必须以相同的顺序相同的字符字符串的实例。
	    	   if (existingConfig.SSID.equals("\""+SSID+"\""))  
	          {  
	                  return existingConfig;  
	          }  
	       }  
	       return null;   
	 }  

	 //接受到消息
	 public void show_result(byte[] buffer,int count) {
			StringBuffer msg = new StringBuffer();                                //创建缓冲区
			TextView tvInfo = (TextView)findViewById(R.id.tvInfo);   //创建 文本显示对象
			tvInfo.setText("");                                                   //清空对象内容 
			for (int i = 0; i < count; i++)
			  msg.append(String.format("0x%x ", buffer[i]));
			//将指定的字符串缓冲的末尾。返回一个局部的格式化字符串，使用所提供的格式和参数，使用用户的默认区域设置。
			
			tvInfo.setText(msg);		                                           //显示到界面上
		}
	 //发送缓冲区数据到网络
	 public void send_buffer_to_network(byte []msg,byte length) {
		 public_info.buf_length = length;
		 public_info.buf = msg;
		 public_info.need_send_cmd = true;
		 vib.vibrate(100);
		 //振动不断为指定的时间。
	 }
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		changed_wifi = false;
		connected_server = false;
		
		set_btn_status(false);                                //wifi设备未连接，设置 屏幕 一些 按钮 不能操作
		connectBtn = (Button)findViewById(R.id.connectBtn);   //创建 连接按钮对象
       //设置此视图的启用状态。在启用状态不同的子类的解释。
		connectBtn.setEnabled(false);                                  //允许连接对象按钮操作
		vib = (Vibrator) getSystemService(Service.VIBRATOR_SERVICE);   //获取手机震动对象
		netMessageHandle = new Handler() {            //蓝牙消息 handler 对象
			public void handleMessage(Message msg) {
			  if (msg.what == 0x1234) {                             //如果消息是 0x1234,则是从 线程中 传输过来的数据  			 
				show_result((byte [])msg.obj,8);                    //将 缓冲区的数据显示到 UI
			  }
			  if (msg.what == 0x1235) {                             //如果消息是 0x1235,则是从 线程中 传输过来的数据  			 
				Toast.makeText(getApplicationContext(), "线程退出:" + msg.obj, Toast.LENGTH_LONG).show();
			  }
			}
		};
		//注册的广播接收器可以运行在主活动线。接收器将被称为任何广播意图匹配滤波器，在主应用程序线程。
		registerReceiver(new BroadcastReceiver() {
			public void onReceive(Context context,Intent intent) {
			  //介绍了对检测到的接入点信息。除了这里描述的属性，他们跟踪质量，噪声，和maxbitrate属性，但目前不到外部客户报告。
				List<ScanResult> results = wifi.getScanResults();
			  if (results.size() < 1) {
				  connectBtn.setEnabled(false);                                  //允许连接对象按钮操作
				  Toast.makeText(getApplicationContext(), "没有找到无线网络", Toast.LENGTH_LONG).show();
				  return;
			  }
			  Spinner spinner = (Spinner)findViewById(R.id.spinner1);       //获取 下拉框控件 对象
		      List<String>list = new ArrayList<String>();                   //创建列表，用于保存wifi设备ssid
		      for (ScanResult result: results) {
		       		list.add(result.SSID);                            //将wifi地址进入到列表
		      }
		      //创建数组适配器
		      ArrayAdapter<String> adapter = new ArrayAdapter<String>(getApplicationContext(),android.R.layout.simple_spinner_item,list);		       	
		      adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);	//设置 下来显示方式	       	
		      spinner.setAdapter(adapter);                                  //将适配器中数据给下拉框对象  
		       			       			       	
		      connectBtn.setEnabled(true);                                  //允许连接对象按钮操作  
			}
			//新的intent过滤器没有数据，一个动作的比赛。如果没有数据的特点是后来的规定，则过滤器将只匹配不包含数据的意图。可用的
		},new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
		
		btnSearchWIFI = (Button)findViewById(R.id.btnSearchWIFI);
		btnSearchWIFI.setOnClickListener(new View.OnClickListener() {
			
			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				wifi = (WifiManager)getSystemService(Context.WIFI_SERVICE);
				if (!wifi.isWifiEnabled())
					if (wifi.getWifiState() != WifiManager.WIFI_STATE_ENABLING)
						wifi.setWifiEnabled(true);        //打开 wifi功能
				wifi.startScan();                         //开始 搜索
				Toast.makeText(getApplicationContext(), "开始搜索无线网络", Toast.LENGTH_LONG).show();
				vib.vibrate(100);                        //震动
			}
		});
		
		
		
		connectBtn.setOnClickListener(new View.OnClickListener() {
			
			@Override
			public void onClick(View v) {
				
				connected_server = false;
				
				Spinner spinner = (Spinner)findViewById(R.id.spinner1);    //获取 下拉框对象    
				String ssid = spinner.getSelectedItem().toString();            //从下拉框中选择项目，并获得它的地址
				current_ssid = ssid;
				
				WifiInfo info = wifi.getConnectionInfo();    //获取当前连接的wifi ssid,以便退出的时候恢复
				old_ssid = info.getSSID();
				
				WifiConfiguration wifiConfig = CreateWifiInfo(           //创建wifiConfiguration
						ssid,"",WifiCipherType.WIFICIPHER_NOPASS);       //  无加密
				
				WifiConfiguration tempConfig = IsExists(ssid);           //如果 ssid  存在，则删除
				if (tempConfig != null)
					wifi.removeNetwork(tempConfig.networkId);
				
				int id = wifi.addNetwork(wifiConfig);                    //加入到网络 
				if (id == -1) {
					Toast.makeText(getApplicationContext(), "加入到网络错误", Toast.LENGTH_LONG).show();
					return;
				}								
				
				boolean ret = wifi.enableNetwork(id, true);              //开启wifi网络
				if (ret) 
				  wifi.saveConfiguration();                              //  保持配置
				
				if (ret) {
					connect_server();                                    //连接服务器
					Toast.makeText(getApplicationContext(), String.format("加入wifi网络 %s 成功",ssid), Toast.LENGTH_SHORT).show();
					changed_wifi = true;															
				} else
					Toast.makeText(getApplicationContext(), String.format("加入wifi网络 %s 失败",ssid), Toast.LENGTH_SHORT).show();
				
				vib.vibrate(100);
			}   
			    
		});
		
		ledonBtn = (Button)findViewById(R.id.ledonBtn);
		ledonBtn.setOnClickListener(new View.OnClickListener() {
			
			@Override
			public void onClick(View arg0) {
				//开 LED 灯
				byte[] msg = new byte[8];
				msg[0] = (byte) 0x81;         //协议头
				msg[1] = (byte) 0x1;          //开灯命令
				msg[7] = (byte) (msg[0] + msg[1] +msg[2] +
						         msg[3] +msg[4] +msg[5] + msg[6]); //校验和
				
				send_buffer_to_network(msg,(byte) msg.length);
				
			}
		});
		
		ledoffBtn = (Button)findViewById(R.id.ledoffBtn);
		ledoffBtn.setOnClickListener(new View.OnClickListener() {
			
			@Override
			public void onClick(View arg0) {
				//关 LED 灯
				byte[] msg = new byte[8];
				msg[0] = (byte) 0x81;         //协议头
				msg[1] = (byte) 0x2;          //关灯命令
				msg[7] = (byte) (msg[0] + msg[1] +msg[2] +
						         msg[3] +msg[4] +msg[5] + msg[6]); //校验和
				
				send_buffer_to_network(msg,(byte) msg.length);
				
			}
		});
		
		jdqonBtn = (Button)findViewById(R.id.jdqonBtn);
		jdqonBtn.setOnClickListener(new View.OnClickListener() {
			
			@Override
			public void onClick(View arg0) {
				//开继电器 
				byte[] msg = new byte[8];
				msg[0] = (byte) 0x81;         //协议头
				msg[1] = (byte) 0x3;          //开继电器命令
				msg[7] = (byte) (msg[0] + msg[1] +msg[2] +
						         msg[3] +msg[4] +msg[5] + msg[6]); //校验和
				
				send_buffer_to_network(msg,(byte) msg.length);
				
			}
		});
		
		jdqoffBtn = (Button)findViewById(R.id.jdqoffBtn);
		jdqoffBtn.setOnClickListener(new View.OnClickListener() {
			
			@Override
			public void onClick(View arg0) {
				//关 继电器
				byte[] msg = new byte[8];
				msg[0] = (byte) 0x81;         //协议头
				msg[1] = (byte) 0x4;          //关继电器命令
				msg[7] = (byte) (msg[0] + msg[1] +msg[2] +
						         msg[3] +msg[4] +msg[5] + msg[6]); //校验和
				
				send_buffer_to_network(msg,(byte) msg.length);
				
			}
		});
		
		edtInfo = (EditText)findViewById(R.id.edtInfo);
		btnSend = (Button)findViewById(R.id.btnSend);
		btnSend.setOnClickListener(new View.OnClickListener() {			
			@Override
			public void onClick(View arg0) {
			  	String strMsg = edtInfo.getText().toString();
			  	if (strMsg.length() == 0) {
			  		Toast.makeText(getApplicationContext(), "文本框内容为空，请输入后操作", Toast.LENGTH_LONG).show();
			  		return;
			  	}
			  	send_buffer_to_network(strMsg.getBytes(),(byte)strMsg.length());
			}
		});
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

}
