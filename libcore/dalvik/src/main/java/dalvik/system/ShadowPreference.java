package dalvik.system;

import java.io.File;

public class ShadowPreference {

    public static final String IMEI_KEY = "shadow_imei";
    public static final String PHONE_KEY = "shadow_phonenumber";
    public static final String LOCATION_KEY = "shadow_location";
    public static final String CONTACTS_KEY = "shadow_contacts";
    public static final String CAMERA_KEY = "shadow_camera";
    public static final String MIC_KEY = "shadow_microphone";
    public static final String ACCOUNT_KEY = "shadow_account";
    public static final String LOGS_KEY = "shadow_logs";
    public static final String SMS_KEY = "shadow_sms";
    public static final String HISTORY_KEY = "shadow_history";
    public static final String CALENDAR_KEY = "shadow_calendar";
    public static final String FEEDS_KEY = "shadow_feeds";

	private static final String underline_path = "/data/data/com.android.settings/";

	private static String getPath(String packageName, String key)
	{
		return underline_path+packageName+"."+key;
	}
	
	public static boolean isShadowed(String packageName, String key)
	{
		File f = new File(getPath(packageName, key));
		return f.exists();
	}

	public static void shadow(String packageName, String key, boolean check)
	{
		File f = new File(getPath(packageName, key));
		if(check)
		{
			if(!f.exists())
			{
				try {
					f.createNewFile();	
				}
				catch(java.io.IOException e)
				{
					e.printStackTrace();
				}
			}
		}
		else
		{
			if(f.exists())
			{
				f.delete();
			}
		}
	}
}
