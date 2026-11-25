import win32clipboard
import win32gui
import win32process
import psutil
import time
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

API_ENDPOINT = "http://localhost:8000/api/v1/events"

def get_clipboard_text():
    try:
        win32clipboard.OpenClipboard()
        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
        elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
            data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT).decode('utf-8')
        else:
            data = None
        win32clipboard.CloseClipboard()
        return data
    except Exception as e:
        try:
            win32clipboard.CloseClipboard()
        except:
            pass
        return None

def get_clipboard_owner():
    try:
        hwnd = win32clipboard.GetClipboardOwner()
        if hwnd:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            try:
                process = psutil.Process(pid)
                return process.name(), pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return "Unknown", pid
    except Exception as e:
        pass
    return "Unknown", 0

def monitor_clipboard():
    logging.info("ClipGuard Agent Started. Monitoring clipboard...")
    last_clipboard_data = get_clipboard_text()
    
    while True:
        try:
            current_data = get_clipboard_text()
            
            # If clipboard changed and has text
            if current_data is not None and current_data != last_clipboard_data:
                process_name, process_id = get_clipboard_owner()
                
                # Send to backend
                event = {
                    "process_name": process_name,
                    "process_id": process_id,
                    "text": current_data,
                    "timestamp": time.time()
                }
                
                try:
                    # In a real environment, this would use mTLS or API keys for auth
                    response = requests.post(API_ENDPOINT, json=event, timeout=2)
                    logging.info(f"Captured event from {process_name} (Risk: {response.json().get('risk', 'N/A')})")
                except requests.exceptions.RequestException as e:
                    logging.error(f"Failed to send event to backend: {e}")
                
                last_clipboard_data = current_data
                
        except Exception as e:
            logging.error(f"Error during polling: {e}")
            
        time.sleep(0.5) # Poll twice a second

if __name__ == "__main__":
    monitor_clipboard()
