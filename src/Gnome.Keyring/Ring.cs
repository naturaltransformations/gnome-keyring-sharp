//
// Gnome.Keyring.Ring.cs
//
// Authors:
//	Gonzalo Paniagua Javier (gonzalo@ximian.com)
//	Alp Toker (alp@atoker.com)
//
// (C) Copyright 2006 Novell, Inc. (http://www.novell.com)
// (C) Copyright 2007 Alp Toker
//

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

using GLib;

namespace Gnome.Keyring
{
    public class Ring
    {
        static string appname;

        private Ring()
        {
        }

        private static class LibGnomeImports
        {
            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_get_info_sync(string keyringName, out IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_info_free(IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_info_get_ctime(IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_info_get_mtime(IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern int gnome_keyring_info_get_lock_timeout(IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern bool gnome_keyring_info_get_is_locked(IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern bool gnome_keyring_info_get_lock_on_idle(IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_set_info_sync(string keyring, IntPtr keyringInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_info_set_lock_timeout(IntPtr keyringInfo, UInt32 timeout);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_info_set_lock_on_idle(IntPtr keyringInfo, bool lockOnIdle);

            [DllImport("libgnome-keyring.dll")]
            public static extern bool gnome_keyring_is_available();

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_lock_all_sync();

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_set_default_keyring_sync(string keyring);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_get_default_keyring_sync(out IntPtr keyring);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_list_keyring_names_sync(out IntPtr keyringList);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_string_list_free(IntPtr stringList);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_create_sync(string keyringName, string password);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_lock_sync(string keyring);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_unlock_sync(string keyring, string password);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_delete_sync(string keyring);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_list_item_ids_sync(string keyring, out IntPtr ids);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_item_get_attributes_sync(string keyring, UInt32 id, out IntPtr attributes);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_find_items_sync(ItemType type, IntPtr attrList, out IntPtr foundList);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_found_list_free(IntPtr foundList);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_find_network_password_sync(string user, string domain, string server,
                string @object, string protocol, string authtype, UInt32 port, out IntPtr passwordList);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_item_create_sync(string keyring,
                ItemType type,
                string displayName,
                IntPtr attributes,
                IntPtr secret,
                bool updateIfExists,
                out UInt32 itemId);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_memory_strdup(string str);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_memory_free(IntPtr str);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_attribute_list_append_string(IntPtr attributes, string name, string val);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_attribute_list_append_uint32(IntPtr attributes, string name, UInt32 val);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_attribute_list_free(IntPtr attributes);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_attribute_list_new();

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_item_delete_sync(string keyring, UInt32 id);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_set_network_password_sync(string keyring,
                string user,
                string domain,
                string server,
                string @object,
                string protocol,
                string authType,
                UInt32 port,
                string password,
                out UInt32 id);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_item_get_info_sync(string keyring, UInt32 id, out IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern ItemType gnome_keyring_item_info_get_type(IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_item_info_get_ctime(IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_item_info_get_mtime(IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_item_info_get_display_name(IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_item_info_get_secret(IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_item_info_free(IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_item_set_info_sync(string keyring, UInt32 id, IntPtr itemInfo);

            [DllImport("libgnome-keyring.dll")]
            public static extern IntPtr gnome_keyring_item_info_new();

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_item_info_set_display_name(IntPtr itemInfo, string displayName);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_item_info_set_type(IntPtr itemInfo, ItemType type);

            [DllImport("libgnome-keyring.dll")]
            public static extern void gnome_keyring_item_info_set_secret(IntPtr itemInfo, string secret);

            [DllImport("libgnome-keyring.dll")]
            public static extern ResultCode gnome_keyring_item_set_attributes_sync(string keyring, UInt32 id, IntPtr attrList);

            // GnomeKeyringAttributeList is a GArray

            [StructLayout(LayoutKind.Sequential)]
            public struct GArray
            {
                public IntPtr data;
                public UInt32 len;
            }

            public enum GnomeKeyringAttributeType : uint
            {
                GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
                GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32
            }

            /*
             * GnomeKeyringAttribute as a C# struct corresponding its C equivalent.
             *
             * IntPtr is used to represent the union
             *
             * union {
             *      char* string; // 8 bytes or 4bytes
             *      guint32 integer; // 4 bytes
             *  } value
             *
             * This works since IntPtr is 4 or 8 bytes according to
             * PlatformTarget.
             *
             */
            [StructLayout(LayoutKind.Sequential)]
            public struct GnomeKeyringAttribute
            {
                public IntPtr name;
                public GnomeKeyringAttributeType type;

                public UInt32 ValueInteger
                {
                    get
                    {
                        return (UInt32)ValueString;
                    }
                }

                public IntPtr ValueString { get; }
            }

            public unsafe static int gnome_item_attribute_list_get_length(IntPtr attrList)
            {
                return (int)(*(GArray*)attrList).len;
            }

            // #define gnome_keyring_attribute_list_index(a, i) g_array_index ((a), GnomeKeyringAttribute, (i))
            // g_array_index  Returns the element of a GArray at the given index.The return value is cast to the given type.
            private unsafe static GnomeKeyringAttribute gnome_keyring_attribute_list_index(IntPtr attrList, Int32 index)
            {
                return ((GnomeKeyringAttribute*)(*(GArray*)attrList).data)[index];
            }

            public static bool gnome_item_attribute_list_index_is_string(IntPtr attrList, Int32 index)
            {
                return gnome_keyring_attribute_list_index(attrList, index).type == GnomeKeyringAttributeType.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
            }

            public static bool gnome_item_attribute_list_index_is_uint32(IntPtr attrList, int index)
            {
                return gnome_keyring_attribute_list_index(attrList, index).type == GnomeKeyringAttributeType.GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32;
            }

            public static IntPtr gnome_item_attribute_list_get_index_string(IntPtr attrList, int index)
            {
                return gnome_keyring_attribute_list_index(attrList, index).ValueString;
            }

            public static UInt32 gnome_item_attribute_list_get_index_uint32(IntPtr attrList, int index)
            {
                return gnome_keyring_attribute_list_index(attrList, index).ValueInteger;
            }

            public static IntPtr gnome_item_attribute_list_get_index_key(IntPtr attrList, int index)
            {
                return gnome_keyring_attribute_list_index(attrList, index).name;
            }
        }



        public static string ApplicationName
        {
            get
            {
                if (appname == null)
                {
                    Assembly assembly = Assembly.GetEntryAssembly();
                    if (assembly == null)
                        throw new Exception("You need to set Ring.ApplicationName.");
                    appname = assembly.GetName().Name;
                }

                return appname;
            }

            set
            {
                if (string.IsNullOrEmpty(value))
                    throw new ArgumentException("Cannot be null or empty", "value");

                appname = value;
            }
        }


        public static bool Available
        {
            get
            {
                return LibGnomeImports.gnome_keyring_is_available();
            }
        }


        public static void LockAll()
        {
            ResultCode result = LibGnomeImports.gnome_keyring_lock_all_sync();
            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
        }


        public static void SetDefaultKeyring(string newKeyring)
        {
            if (newKeyring == null)
                throw new ArgumentNullException("newKeyring");
            ResultCode result = LibGnomeImports.gnome_keyring_set_default_keyring_sync(newKeyring);
            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
        }

        public static string GetDefaultKeyring()
        {
            ResultCode result = LibGnomeImports.gnome_keyring_get_default_keyring_sync(out IntPtr keyring_name);
            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
            return GLib.Marshaller.PtrToStringGFree(keyring_name);
        }

        public static string[] GetKeyrings()
        {
            ResultCode result = LibGnomeImports.gnome_keyring_list_keyring_names_sync(out IntPtr keyring_list);
            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
            var retval = Marshaller.ListPtrToArray<string>(keyring_list, typeof(GLib.List), false, false);
            LibGnomeImports.gnome_keyring_string_list_free(keyring_list);
            return retval;
        }


        public static void CreateKeyring(string name, string password)
        {
            ResultCode result = LibGnomeImports.gnome_keyring_create_sync(name, password);
            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
        }


        public static void Lock(string keyring)
        {
            if (keyring == null)
                throw new ArgumentNullException("keyring");

            ResultCode result = LibGnomeImports.gnome_keyring_lock_sync(keyring);
            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
        }


        public static void Unlock(string keyring, string password)
        {
            ResultCode result = LibGnomeImports.gnome_keyring_unlock_sync(keyring, password);

            if (!(result == ResultCode.Ok || result == ResultCode.AlreadyUnlocked))
            {
                throw new KeyringException(result);
            }
        }

        public static void DeleteKeyring(string keyring)
        {
            if (keyring == null)
                throw new ArgumentNullException("keyring");

            ResultCode result = LibGnomeImports.gnome_keyring_delete_sync(keyring);
            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
        }


        public static int[] ListItemIDs(string keyring)
        {
            if (keyring == null)
                throw new ArgumentNullException("keyring");

            ResultCode result = LibGnomeImports.gnome_keyring_list_item_ids_sync(keyring, out IntPtr idlist);

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }

            IntPtr[] ptrArray = Marshaller.ListPtrToArray<IntPtr>(idlist, typeof(GLib.List), true, false);
            int[] ids = new int[ptrArray.Length];
            for (int i = 0; i < ptrArray.Length; i++)
            {
                ids[i] = ptrArray[i].ToInt32();
            }

            return ids;
        }


        static void NativeListFromAttributes(IntPtr attrList, Hashtable attributes)
        {
            foreach (string key in attributes.Keys)
            {
                if (attributes[key] is string)
                {
                    LibGnomeImports.gnome_keyring_attribute_list_append_string(attrList, key, (string)attributes[key]);
                }
                else if (attributes[key] is int)
                {
                    LibGnomeImports.gnome_keyring_attribute_list_append_uint32(attrList, key, (uint)((int)attributes[key]));
                }
                else
                {
                    throw new ArgumentException(String.Format("Attribute \"{0}\" has invalid parameter type: {1}", key, attributes[key].GetType()));
                }
            }
        }

        static void AttributesFromNativeList(IntPtr attrList, Hashtable attributes)
        {
            int listLength = LibGnomeImports.gnome_item_attribute_list_get_length(attrList);
            for (int i = 0; i < listLength; i++)
            {
                string key = Marshal.PtrToStringAnsi(LibGnomeImports.gnome_item_attribute_list_get_index_key(attrList, i));
                if (LibGnomeImports.gnome_item_attribute_list_index_is_string(attrList, i))
                {
                    attributes[key] = Marshal.PtrToStringAnsi(LibGnomeImports.gnome_item_attribute_list_get_index_string(attrList, i));
                }
                else if (LibGnomeImports.gnome_item_attribute_list_index_is_uint32(attrList, i))
                {
                    attributes[key] = (int)LibGnomeImports.gnome_item_attribute_list_get_index_uint32(attrList, i);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct GnomeKeyringFound
        {
            public IntPtr keyring;
            public UInt32 item_id;
            public IntPtr attrList;
            public IntPtr secret;
        }


        static readonly ItemData[] empty_item_data = new ItemData[0];

        public static ItemData[] Find(ItemType type, Hashtable atts)
        {
            if (atts == null)
                throw new ArgumentNullException("atts");

            IntPtr attrList = LibGnomeImports.gnome_keyring_attribute_list_new();

            NativeListFromAttributes(attrList, atts);

            ResultCode result = LibGnomeImports.gnome_keyring_find_items_sync(type, attrList, out IntPtr passwordList);

            if (result == ResultCode.Denied || result == ResultCode.NoMatch)
            {
                return empty_item_data;
            }

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }

            IntPtr[] passwordStructs = Marshaller.ListPtrToArray<IntPtr>(passwordList, typeof(GLib.List), false, false);

            List<GnomeKeyringFound> passwords = new List<GnomeKeyringFound>();

            foreach (IntPtr ptr in passwordStructs)
            {
                passwords.Add((GnomeKeyringFound)Marshal.PtrToStructure(ptr, typeof(GnomeKeyringFound)));
            }

            ArrayList list = new ArrayList();
            foreach (var password in passwords)
            {
                ItemData found = ItemData.GetInstanceFromItemType(type);
                found.ItemID = (int)password.item_id;
                found.Secret = Marshal.PtrToStringAnsi(password.secret);
                found.Keyring = Marshal.PtrToStringAnsi(password.keyring);
                found.Attributes = new Hashtable();
                AttributesFromNativeList(password.attrList, found.Attributes);
                found.SetValuesFromAttributes();
                list.Add(found);
            }

            LibGnomeImports.gnome_keyring_found_list_free(passwordList);
            LibGnomeImports.gnome_keyring_attribute_list_free(attrList);

            return (ItemData[])list.ToArray(typeof(ItemData));
        }

        [StructLayout(LayoutKind.Sequential)]
        struct GnomeKeyringNetworkPasswordData
        {
            public IntPtr keyring;
            public UInt32 item_id;

            public IntPtr protocol;
            public IntPtr server;
            public IntPtr @object;
            public IntPtr authtype;
            public UInt32 port;

            public IntPtr user;
            public IntPtr domain;
            public IntPtr password;
        }

        static readonly NetItemData[] empty_net_item_data = new NetItemData[0];
        public static NetItemData[] FindNetworkPassword(string user, string domain, string server, string obj,
                                    string protocol, string authtype, int port)
        {
            ResultCode result = LibGnomeImports.gnome_keyring_find_network_password_sync(user, domain, server, obj, protocol, authtype, (uint)port, out IntPtr passwordList);

            if (result == ResultCode.Denied || result == ResultCode.NoMatch)
            {
                return empty_net_item_data;
            }

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }

            IntPtr[] passwordStructs = Marshaller.ListPtrToArray<IntPtr>(passwordList, typeof(GLib.List), false, false);
            List<GnomeKeyringNetworkPasswordData> passwords = new List<GnomeKeyringNetworkPasswordData>();

            foreach (IntPtr ptr in passwordStructs)
            {
                passwords.Add((GnomeKeyringNetworkPasswordData)Marshal.PtrToStructure(ptr, typeof(GnomeKeyringNetworkPasswordData)));
            }

            ArrayList list = new ArrayList();
            foreach (var password in passwords)
            {
                NetItemData found = new NetItemData();
                found.Keyring = Marshal.PtrToStringAnsi(password.keyring);
                found.ItemID = (int)password.item_id;
                found.Secret = Marshal.PtrToStringAnsi(password.password);
                found.Attributes = new Hashtable();

                SetAttributeIfNonNull(found.Attributes, "protocol", password.protocol);
                SetAttributeIfNonNull(found.Attributes, "server", password.server);
                SetAttributeIfNonNull(found.Attributes, "object", password.@object);
                SetAttributeIfNonNull(found.Attributes, "authtype", password.authtype);
                SetAttributeIfNonNull(found.Attributes, "user", password.user);
                SetAttributeIfNonNull(found.Attributes, "domain", password.domain);

                if (password.port != 0)
                {
                    found.Attributes["port"] = (int)password.port;
                }

                found.SetValuesFromAttributes();
                list.Add(found);
            }

            return (NetItemData[])list.ToArray(typeof(NetItemData));
        }

        static void SetAttributeIfNonNull(Hashtable attrs, string key, IntPtr maybeString)
        {
            if (maybeString != IntPtr.Zero)
            {
                attrs[key] = Marshal.PtrToStringAnsi(maybeString);
            }
        }


        public static int CreateItem(string keyring, ItemType type, string displayName, Hashtable attributes,
                        string secret, bool updateIfExists)
        {
            IntPtr secure_secret = LibGnomeImports.gnome_keyring_memory_strdup(secret);
            IntPtr attrs = LibGnomeImports.gnome_keyring_attribute_list_new();

            NativeListFromAttributes(attrs, attributes);

            ResultCode result = LibGnomeImports.gnome_keyring_item_create_sync(keyring, type, displayName, attrs, secure_secret, updateIfExists, out uint id);

            LibGnomeImports.gnome_keyring_attribute_list_free(attrs);
            LibGnomeImports.gnome_keyring_memory_free(secure_secret);

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }

            return (int)id;
        }


        public static void DeleteItem(string keyring, int id)
        {
            if (keyring == null)
                throw new ArgumentNullException("keyring");

            ResultCode result = LibGnomeImports.gnome_keyring_item_delete_sync(keyring, (uint)id);

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
        }


        public static int CreateOrModifyNetworkPassword(string keyring, string user, string domain, string server, string obj,
                                string protocol, string authtype, int port, string password)
        {
            ResultCode result = LibGnomeImports.gnome_keyring_set_network_password_sync(keyring, user, domain, server, obj, protocol, authtype, (uint)port, password, out uint id);

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }

            return (int)id;
        }


        public static ItemData GetItemInfo(string keyring, int id)
        {
            if (keyring == null)
                throw new ArgumentNullException("keyring");

            ResultCode result = LibGnomeImports.gnome_keyring_item_get_info_sync(keyring, (uint)id, out IntPtr itemInfo);

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }

            ItemData item = ItemData.GetInstanceFromItemType(LibGnomeImports.gnome_keyring_item_info_get_type(itemInfo));
            item.Attributes = new Hashtable
            {
                ["keyring_ctime"] = GLib.Marshaller.time_tToDateTime(LibGnomeImports.gnome_keyring_item_info_get_ctime(itemInfo)),
                ["keyring_mtime"] = GLib.Marshaller.time_tToDateTime(LibGnomeImports.gnome_keyring_item_info_get_mtime(itemInfo)),
                ["name"] = Marshal.PtrToStringAnsi(LibGnomeImports.gnome_keyring_item_info_get_display_name(itemInfo))
            };

            item.Keyring = keyring;
            item.ItemID = id;
            item.Secret = Marshal.PtrToStringAnsi(LibGnomeImports.gnome_keyring_item_info_get_secret(itemInfo));

            item.SetValuesFromAttributes();

            LibGnomeImports.gnome_keyring_item_info_free(itemInfo);

            return item;
        }


        public static void SetItemInfo(string keyring, int id, ItemType type, string displayName, string secret)
        {
            if (keyring == null)
                throw new ArgumentNullException("keyring");

            IntPtr itemInfo = LibGnomeImports.gnome_keyring_item_info_new();
            LibGnomeImports.gnome_keyring_item_info_set_display_name(itemInfo, displayName);
            LibGnomeImports.gnome_keyring_item_info_set_type(itemInfo, type);
            LibGnomeImports.gnome_keyring_item_info_set_secret(itemInfo, secret);

            ResultCode result = LibGnomeImports.gnome_keyring_item_set_info_sync(keyring, (uint)id, itemInfo);

            LibGnomeImports.gnome_keyring_item_info_free(itemInfo);

            if (result != ResultCode.Ok)
            {
                throw new KeyringException(result);
            }
        }

		public static Hashtable GetItemAttributes (string keyring, int id)
		{
			if (keyring == null)
				throw new ArgumentNullException ("keyring");

            Hashtable retVal = new Hashtable();

            ResultCode result = LibGnomeImports.gnome_keyring_item_get_attributes_sync (keyring, (uint)id, out IntPtr attributes);

			if (result != ResultCode.Ok) {
				throw new KeyringException (result);
			}

			AttributesFromNativeList (attributes, retVal);

			LibGnomeImports.gnome_keyring_attribute_list_free (attributes);

			return retVal;
		}


		public static void SetItemAttributes (string keyring, int id, Hashtable atts)
		{
			if (keyring == null)
				throw new ArgumentNullException ("keyring");

			IntPtr attrList = LibGnomeImports.gnome_keyring_attribute_list_new ();
			foreach (string key in atts.Keys) {
				if (atts[key] is string) {
					LibGnomeImports.gnome_keyring_attribute_list_append_string (attrList, key, (string)atts[key]);
				} else if (atts[key] is int) {
					LibGnomeImports.gnome_keyring_attribute_list_append_uint32 (attrList, key, (uint)((int)atts[key]));
				} else {
					throw new ArgumentException (String.Format ("Attribute \"{0}\" has invalid parameter type: {1}", key, atts[key].GetType ()));
				}
			}

			ResultCode result = LibGnomeImports.gnome_keyring_item_set_attributes_sync (keyring, (uint)id, attrList);

			LibGnomeImports.gnome_keyring_attribute_list_free (attrList);

			if (result != ResultCode.Ok) {
				throw new KeyringException (result);
			}
		}


        public static KeyringInfo GetKeyringInfo (string keyring)
		{
			if (keyring == null)
				throw new ArgumentNullException ("keyring");

			IntPtr keyring_info = IntPtr.Zero;
			ResultCode result = LibGnomeImports.gnome_keyring_get_info_sync (keyring, out keyring_info);

			if (result != ResultCode.Ok) {
				throw new KeyringException (result);
			}

			DateTime ctime = GLib.Marshaller.time_tToDateTime (LibGnomeImports.gnome_keyring_info_get_ctime (keyring_info));
			DateTime mtime = GLib.Marshaller.time_tToDateTime (LibGnomeImports.gnome_keyring_info_get_mtime (keyring_info));
			KeyringInfo retval = new KeyringInfo (keyring,
				LibGnomeImports.gnome_keyring_info_get_lock_on_idle (keyring_info),
				LibGnomeImports.gnome_keyring_info_get_lock_timeout (keyring_info),
				mtime,
				ctime,
				LibGnomeImports.gnome_keyring_info_get_is_locked (keyring_info)
				);


			LibGnomeImports.gnome_keyring_info_free (keyring_info);
			return retval;
		}


		public static void SetKeyringInfo (string keyring, KeyringInfo info)
		{
			if (keyring == null)
				throw new ArgumentNullException ("keyring");

			if (info == null)
				throw new ArgumentNullException ("info");

            ResultCode result = LibGnomeImports.gnome_keyring_get_info_sync(keyring, out IntPtr keyring_info);

            if (result != ResultCode.Ok) {
				throw new KeyringException (result);
			}

			LibGnomeImports.gnome_keyring_info_set_lock_timeout (keyring_info, (uint)info.LockTimeoutSeconds);
			LibGnomeImports.gnome_keyring_info_set_lock_on_idle (keyring_info, info.LockOnIdle);

			result = LibGnomeImports.gnome_keyring_set_info_sync (keyring, keyring_info);

			LibGnomeImports.gnome_keyring_info_free (keyring_info);

			if (result != ResultCode.Ok) {
				throw new KeyringException (result);
			}
		}

		[Obsolete ("Item ACLs are deprecated.  GetItemACL never returns any ACLs")]
		public static ArrayList GetItemACL (string keyring, int id)
		{
			if (keyring == null)
				throw new ArgumentNullException ("keyring");

			return new ArrayList ();
		}

		[Obsolete("Item ACLs are deprecated.  SetItemACL has no effect.")]
		public static void SetItemACL (string keyring, int id, ICollection acls)
		{
			if (acls == null)
				throw new ArgumentNullException ("acls");

			ItemACL[] arr = new ItemACL[acls.Count];
			acls.CopyTo (arr, 0);
			SetItemACL (keyring, id, arr);
		}

		[Obsolete("Item ACLs are deprecated.  SetItemACL has no effect.")]
		public static void SetItemACL (string keyring, int id, ItemACL [] acls)
		{
			if (keyring == null)
				throw new ArgumentNullException ("keyring");

			if (acls == null)
				throw new ArgumentNullException ("acls");

			if (acls.Length == 0)
				throw new ArgumentException ("Empty ACL set.", "acls");
		}
	}
}
