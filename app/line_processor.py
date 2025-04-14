import docker
import os
import re
import time
import logging
import threading
from threading import Thread, Lock
from notifier import send_notification
from load_config import GlobalConfig



class LogProcessor:
    """
    LoggiFly seearches for patterns that signal the start of a log entry to detect entries that span over multiple lines.
    That is what these patterns are for.
    """
    STRICT_PATTERNS = [
            
        # combined timestamp and log level
        r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d{3})?\] \[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]", # 
        r"^\d{4}-\d{2}-\d{2}(?:, | )\d{2}:\d{2}:\d{2}(?:,\d{3})? (?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)",
        
        # ISO in brackets
        r"^\[\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\]", # [2025-02-17T03:23:07Z] or [2025-02-17 04:22:59 +0100] or [2025-02-18T03:23:05.436627]

        # Months in brackets
        r"^\[(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\]",                                                  # [Feb 17, 2025 10:13:02]
        r"^\[\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\]", # [17/Feb/2025:10:13:02 +0000]

        # ISO without brackes
        r"^\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b",

        # Months without brackets
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\b",
        r"\b\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\b",   # 17/Feb/2025:10:13:02 +0000
        
        # Unix-like Timestamps
        r"^\[\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d{2,6}\]",
        
        # Log-Level at the beginning of the line
        r"^\[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]",
        r"^\((?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\)"
    ]

    FLEX_PATTERNS = [
            # ----------------------------------------------------------------
            # Generic Timestamps (Fallback)
            # ----------------------------------------------------------------
            
            r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b",
            r"\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b", # 2025-02-17T03:23:07Z
            r"\b(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])-\d{4} \d{2}:\d{2}:\d{2}\b",
            r"(?i)\b\d{2}\/\d{2}\/\d{4}(?:,\s+|:|\s+])\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?\b",
            r"\b\d{10}\.\d+\b",                                                          # 1739762586.0394847
        
            # ----------------------------------------------------------------
            # Log-Level (Fallback)
            # ----------------------------------------------------------------
            r"(?i)(?<=^)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",      
            r"(?i)(?<=\s)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",
            r"(?i)\[(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\]",
            r"(?i)\((?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\)",

            # ## TESTING BECAUSE IT DOES NOT WORK FOR IMMICH SERVER LOGS
            r"(?i)\d{2}/\d{2}/\d{4},\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)",
        ]
            
    COMPILED_STRICT_PATTERNS = [re.compile(pattern, re.ASCII) for pattern in STRICT_PATTERNS]
    COMPILED_FLEX_PATTERNS = [re.compile(pattern, re.ASCII) for pattern in FLEX_PATTERNS]

    def __init__(self, config: GlobalConfig, container, container_stop_event): # container_stop_event, shutdown_event, restart_event
        # self.shutdown_event = shutdown_event
        # self.restart_event = restart_event
        
        self.container_stop_event = container_stop_event
        self.container = container
        self.container_name = container.name

        self.patterns = []
        self.patterns_count = {pattern: 0 for pattern in self.__class__.COMPILED_STRICT_PATTERNS + self.__class__.COMPILED_FLEX_PATTERNS}
        self.lock_buffer = Lock()
        self.flush_thread_stopped = threading.Event()
        self.flush_thread_stopped.set()
        self.waiting_for_pattern = False
        self.valid_pattern = False
        
        self.load_config_variables(config)

        
    
    def load_config_variables(self, config):
        self.config = config
        self.container_keywords = self.config.global_keywords.keywords.copy()
        self.container_keywords.extend(keyword for keyword in self.config.containers[self.container_name].keywords if keyword not in self.container_keywords)
        self.container_keywords_with_attachment = self.config.global_keywords.keywords_with_attachment.copy()
        self.container_keywords_with_attachment.extend(keyword for keyword in self.config.containers[self.container_name].keywords_with_attachment if keyword not in self.container_keywords_with_attachment)
        self.container_action_keywords = [keyword for keyword in self.config.containers[self.container_name].action_keywords]

        self.lines_number_attachment = self.config.containers[self.container_name].attachment_lines or self.config.settings.attachment_lines
        self.multi_line_config = self.config.settings.multi_line_entries
        self.notification_cooldown = self.config.containers[self.container_name].notification_cooldown or self.config.settings.notification_cooldown
        self.time_per_keyword = {}  
        self.action_cooldown = self.config.containers[self.container_name].action_cooldown or self.config.settings.action_cooldown or 300
        self.last_action_time = None

        for keyword in self.container_keywords + self.container_keywords_with_attachment:
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                self.time_per_keyword[keyword["regex"]] = 0
            else:
                self.time_per_keyword[keyword] = 0  
                    
        if self.multi_line_config is True:
            self.line_count = 0
            self.line_limit = 300
            if self.valid_pattern is False:
                try:
                    log_tail = self.container.logs(tail=100).decode("utf-8")
                    self._find_pattern(log_tail)
                except Exception as e:
                    logging.error(f"Could not read logs of Container {self.container_name}: {e}")
                if self.valid_pattern:
                    logging.debug(f"{self.container.name}: Mode: Multi-Line. Found starting pattern(s) in logs.")
                else:
                    logging.debug(f"{self.container.name}: Mode: Single-Line. Could not find starting pattern in the logs. Continuing the search in the next {self.line_limit - self.line_count} lines")

        
            self.buffer = []
            self.log_stream_timeout = 1 # self.config.settings.flush_timeout Not an supported setting (yet)
            self.log_stream_last_updated = time.time()
            # Start Background-Thread for Timeout
            self._start_flush_thread()
                

            
    def _container_action(self, action, log_line, found):
        try: 
            if action == "stop":
                logging.info(f"Stopping Container: {self.container_name}.")
                container = self.container
                container.stop()
                logging.info(f"Container {self.container_name} has been stopped")
            elif action == "restart":
                logging.info(f"Restarting Container: {self.container_name}.")
                container = self.container
                container.stop()
                time.sleep(3)
                container.start()
                logging.info(f"Container {self.container_name} has been restarted")
        except Exception as e:
            logging.error(f"Failed to {action} {self.container_name}: {e}")
        

    def _find_pattern(self, line_s):
        self.waiting_for_pattern = True
        for line in line_s.splitlines():
            clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
            self.line_count += 1
            for pattern in self.__class__.COMPILED_STRICT_PATTERNS:
                if pattern.search(clean_line):
                    self.patterns_count[pattern] += 1
                    break
            else:
                for pattern in self.__class__.COMPILED_FLEX_PATTERNS:
                    if pattern.search(clean_line):
                        self.patterns_count[pattern] += 1
                        break
  
        sorted_patterns = sorted(self.patterns_count.items(), key=lambda x: x[1], reverse=True)
        threshold = max(5, int(self.line_count * 0.075))

        for pattern in sorted_patterns:
            if pattern[0] not in self.patterns and pattern[1] > threshold:
                self.patterns.append(pattern[0])
                logging.debug(f"{self.container_name}: Found pattern: {pattern[0]} with {pattern[1]} matches of {self.line_count} lines. {round(pattern[1] / self.line_count * 100, 2)}%")
                self.valid_pattern = True
        if self.patterns == []:
            self.valid_pattern = False
        if self.line_count >= self.line_limit:
            if self.patterns == []:
                logging.info(f"{self.container_name}: No pattern found in logs after {self.line_limit} lines. Mode: single-line")
            # else:   
            #     logging.debug(f"Container: {self.container_name}: Found pattern(s) in logs. Stopping the search now after {self.line_limit}] lines. Mode: multi-line.\Patterns found: {self.patterns}")
                #logging.debug(f"Container: {self.container_name}: Patterns found: {self.patterns}")

        self.waiting_for_pattern = False


    def _start_flush_thread(self):
    # Every second the buffer (with log lines that should belong to the same entry) gets flushed
        def check_flush():
            self.flush_thread_stopped.clear()
            while True:
                if self.container_stop_event.is_set(): # self.shutdown_event.is_set() or 
                    time.sleep(4)
                    if self.container_stop_event.is_set():
                        break
                if self.multi_line_config is False:
                    break
                with self.lock_buffer:
                    if (time.time() - self.log_stream_last_updated > self.log_stream_timeout) and self.buffer:
                        self._handle_and_clear_buffer()
                time.sleep(1)
            self.flush_thread_stopped.set()
            logging.debug(f"Flush Thread stopped for Container {self.container_name}")
            
        if self.flush_thread_stopped.is_set():
            self.flush_thread = Thread(target=check_flush, daemon=True)
            self.flush_thread.start()
            #logging.debug(f"Flush thread started for {self.container.name}")
        #else:
            #logging.debug(f"Flush thread already running for {self.container.name}")


    # This function gets called from outside this class by the monitor_container_logs function in app.py
    # If the user disables multi_line_entries or if there are no patterns detected (yet) the program switches to single-line mode
    # In single-line mode the line gets processed and searched for keywords instantly instead of going into the buffer first
    def process_line(self, line):
        clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        if self.multi_line_config == False:
            self._search_and_send(clean_line)
        else:
            if self.line_count < self.line_limit:
                self._find_pattern(clean_line)
            if self.valid_pattern == True:
                self._process_multi_line(clean_line)
            else:
                self._search_and_send(clean_line)
        
            

    def _process_multi_line(self, line):
        # When the pattern gets updated by _find_pattern() this function waits 
        while self.waiting_for_pattern is True:
            time.sleep(1)

        for pattern in self.patterns:
            # If there is a pattern in the line idicating a new log entry the buffer gets flushed and the line gets appended to the buffer           
            if pattern.search(line):
                if self.buffer:
                    self._handle_and_clear_buffer()
                self.buffer.append(line)
                match = True
                break
            else:
                match = False
        # If the line is not a new entry (no pattern was found) it gets appended to the buffer
        if match is False:
            if self.buffer:
                self.buffer.append(line)
            else:
                # Fallback: Unexpected Format 
                self.buffer.append(line)
        self.log_stream_last_updated = time.time()

    # This function is called either when the buffer is flushed every second 
    # or if a new log entry was found which means everything in the buffer is one complete log entry
    def _handle_and_clear_buffer(self):
        message = "\n".join(self.buffer)
        self._search_and_send(message)
        self.buffer.clear()


    def _search_keyword(self, log_line, keyword, ignore_keyword_time=False):
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                regex_keyword = keyword["regex"]
                if ignore_keyword_time or time.time() - self.time_per_keyword.get(regex_keyword) >= int(self.notification_cooldown):
                    if re.search(regex_keyword, log_line, re.IGNORECASE):
                        self.time_per_keyword[regex_keyword] = time.time()
                        return f"regex: {regex_keyword}"
            else:
                if ignore_keyword_time or time.time() - self.time_per_keyword.get(keyword) >= int(self.notification_cooldown):
                    if str(keyword).lower() in log_line.lower():
                        self.time_per_keyword[keyword] = time.time()
                        return keyword
            return None
    
    # Here the line is searchd for simple keywords or regex patterns
    def _search_and_send(self, log_line):
        keywords_with_attachment_found = [] 
        keywords_found = []
        # Search for normal keywords
        for keyword in self.container_keywords:
            found = self._search_keyword(log_line, keyword)
            if found:
                keywords_found.append(found)
        # Search for Keywords with attachment
        for keyword in self.container_keywords_with_attachment:
            found = self._search_keyword(log_line, keyword)
            if found:
                keywords_with_attachment_found.append(found)        
        # Trigger notification if keywords have been found
        if keywords_with_attachment_found:
            formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(log_line.splitlines()) + "\n   -----------------------"
            logging.info(f"The following keywords were found in {self.container_name}: {keywords_with_attachment_found + keywords_found}. (A Logfile will be attached){formatted_log_entry}" 
                        if len(keywords_with_attachment_found + keywords_found) > 1 
                        else f"'{keywords_with_attachment_found[0]}' was found in {self.container_name}{formatted_log_entry}"
                        )
            self._send_message(log_line, keywords_with_attachment_found, send_attachment=True)
        elif keywords_found:
            formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(log_line.splitlines()) + "\n   -----------------------"
            logging.info(f"The following keywords were found in {self.container_name}: {keywords_found}{formatted_log_entry}"
                         if len(keywords_found + keywords_with_attachment_found) > 1 
                         else f"'{keywords_found[0]}' was found in {self.container_name}{formatted_log_entry}"
                         )
            self._send_message(log_line, keywords_found, send_attachment=False)
            
        # Keywords that trigger a restart
        for keyword in self.container_action_keywords:
            if self.last_action_time is None or (self.last_action_time is not None and time.time() - self.last_action_time >= max(int(self.action_cooldown), 60)):
                if isinstance(keyword, dict) and keyword.get("stop") is not None:
                    action_keyword = keyword.get("stop")
                    found = self._search_keyword(log_line, action_keyword, ignore_keyword_time=True)
                    action = ("stop") if found else None
                elif isinstance(keyword, dict) and keyword.get("restart") is not None:
                    action_keyword = keyword.get("restart")
                    found = self._search_keyword(log_line, action_keyword, ignore_keyword_time=True)
                    action = ("restart") if found else None
                if found:
                    formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(log_line.splitlines()) + "\n   -----------------------"
                    logging.info(f"{'Stopping' if action == 'stop' else 'Restarting'} {self.container_name} because Keyword: {found} was found in {formatted_log_entry}")
                    self._send_message(log_line, found, send_attachment=False, action=action)
                    self._container_action(action, log_line, found)
                    self.last_action_time = time.time()
                    break
            

    def _log_attachment(self):  
        base_name = f"last_{self.lines_number_attachment}_lines_from_{self.container_name}.log"

        def find_available_name(filename, number=1):
            # Create different file name with number if it already exists (in case of many notifications at same time)
            new_name = f"{filename.rsplit('.', 1)[0]}_{number}.log"
            if os.path.exists(new_name):
                return find_available_name(filename, number + 1)
            return new_name
        
        if os.path.exists(base_name):
            file_name = find_available_name(base_name)
        else:
            file_name = base_name

        try:
            file_name = f"last_{self.lines_number_attachment}_lines_from_{self.container_name}.log"
            log_tail = self.container.logs(tail=self.lines_number_attachment).decode("utf-8")
            with open(file_name, "w") as file:  
                file.write(log_tail)
                return file_name
        except Exception as e:
            logging.error(f"Could not read logs of Container {self.container_name}: {e}")
            return None

    def _send_message(self, message, keyword_list, send_attachment=False, action=None):

        if isinstance(keyword_list, list) and len(keyword_list) == 1:
            keyword = keyword_list[0] if "regex" not in keyword_list[0] else "Regex-Pattern: " + "'" + keyword_list[0].split(":")[1] 
            title = f"'{keyword}' found in {self.container.name}"
        elif isinstance(keyword_list, list) and len(keyword_list) > 2:
            joined_keywords = ', '.join(f"'{word}'" for word in keyword_list)
            title = f"The following keywords were found in {self.container.name}: {joined_keywords}"
        elif isinstance(keyword_list, list) and len(keyword_list) == 2:
            joined_keywords = ' and '.join(f"'{word}'" for word in keyword_list)
            title = f"{joined_keywords} found in {self.container.name}"
        else:
            title = f"{self.container.name}"

        if isinstance(keyword_list, str):
            keyword = keyword_list if "regex" not in keyword_list else "Regex-Pattern: " + "'" + keyword_list.split(":")[1] 
        if action:
            title = f"{'Stopping' if action == 'stop' else 'Restarting'} {self.container.name} because keyword '{keyword}' was found"


        if send_attachment:
            file_name = self._log_attachment()
            if file_name and isinstance(file_name, str) and os.path.exists(file_name):
                send_notification(self.config, self.container_name, message, title, file_name)     
                if os.path.exists(file_name):
                    os.remove(file_name)
                    logging.debug(f"The file {file_name} was deleted.")
                else:
                    logging.debug(f"The file {file_name} does not exist.") 

        else:
            send_notification(self.config, self.container_name, title, message,  None)





