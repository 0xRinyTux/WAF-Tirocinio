import asyncio
import sys
import json
import requests
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "mistral"   # oppure mistral
TARGET_IP = "192.168.16.1"
TARGET_PORT = 5000


SYSTEM_PROMPT = r"""
You are a security code auditor AI.

You must respond ONLY with valid JSON. Do not include markdown formatting.

Format 1 - To call a tool:
{
  "action": "call_tool",
  "tool": "tool_name",
  "arguments": { "arg_name": "arg_value" }
}

Format 2 - To add a regex rule (SHORTCUT):
{
  "action": "add_blocking_rule_regex",
  "regex_pattern": "your_regex_here"
}

Format 3 - To finish:
{
  "action": "final",
  "report": "text"
}

Available tools:
- list_files(path): Lister for files.
- read_file_content(file_path): Reader for code.

Negative Constraints:
- DO NOT generate code blocks or explanations outside the JSON.
- DO NOT output multiple JSON objects.
- DO NOT read test.py and firegex_mcp_server.py

Rules:
1. Output MUST be valid JSON.
2. Escape backslashes in regex (e.g., "\\d" not "\d").
3. IMPORTANT: Output only ONE action. Do not generate a sequence of actions. Wait for the tool output before generating the next action.
4. IMPORTANT: Always use "." as the path for 'list_files'. Do not invent paths like '/path/to/project'.
"""

def ask_llm(messages):
    print(f"   >> 💭 Stream Output: ", end="", flush=True)

    try:
        # Use stream=True to process output token by token
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": messages,
                "stream": True,
                "options": {
                    "stop": ["\n\n", "```\n"] # Optional: try to stop on double newlines if it helps
                }
            },
            stream=True
        )
        
        full_response = ""
        brace_count = 0
        in_json = False
        start_json = False

        for line in response.iter_lines():
            if line:
                try:
                    chunk = json.loads(line)
                    if "message" in chunk:
                        content = chunk["message"].get("content", "")
                        sys.stdout.write(content)
                        sys.stdout.flush()
                        full_response += content
                        
                        # Real-time JSON detection to stop hallucinated chains
                        for char in content:
                            if char == '{':
                                start_json = True
                                in_json = True
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                                if start_json and brace_count == 0:
                                    # We found a complete JSON object. Stop listening.
                                    print("\n   >> 🛑 STOPPING GENERATION (Action Detected)")
                                    response.close() # Close connection to stop LLM
                                    return full_response

                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    pass
        print("\n")
        return full_response
    except Exception as e:
        print(f"\nError communicating with Ollama: {e}")
        return full_response

def parse_llm_output(text):
    try:
        # Cleanup markdown and whitespace
        clean_text = text.strip()
        if clean_text.startswith("```"):
            lines = clean_text.split("\n")
            if lines[0].strip().startswith("```"):
                 lines = lines[1:]
            if lines[-1].strip() == "```":
                 lines = lines[:-1]
            clean_text = "\n".join(lines)
        
        # Robust parsing: Stop at the first complete JSON object
        possible_json = ""
        depth = 0
        found = False
        
        # Scan for the first '{'
        start_idx = clean_text.find('{')
        if start_idx == -1:
            return None, None, None
            
        clean_text = clean_text[start_idx:]
        
        for char in clean_text:
            possible_json += char
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    found = True
                    break
        
        if found:
            clean_text = possible_json

        data = json.loads(clean_text)
        action = data.get("action")
        
        if action == "call_tool":
            return "tool", data.get("tool"), data.get("arguments", {})
        elif action == "add_blocking_rule_regex": # Catch simple JSON format without tool wrapper
             return "tool", "add_blocking_rule_regex", {"regex_pattern": data.get("regex_pattern")}
        elif action == "final":
            return "final", data.get("report"), None
        # Robust Fallback: If LLM puts tool name directly in 'action'
        elif action in ["list_files", "read_file_content", "add_blocking_rule_regex"]:
             return "tool", action, data.get("arguments", {})
            
    except json.JSONDecodeError:
        print("Failed to parse JSON")
        pass
        
    return None, None, None


async def main():

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["firegex_mcp_server.py"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:

            await session.initialize()

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "Analyze the current directory ('.'). Read source code files to find vulnerabilities, then apply blocking regex rules."}
            ]

            while True:

                llm_response = ask_llm(messages)
                print("\nLLM:\n", llm_response)

                action, tool_name, args = parse_llm_output(llm_response)

                if action == "final":
                    print("\n=== FINAL REPORT ===")
                    print(tool_name)
                    break

                if action == "tool":
                    if tool_name == "add_blocking_rule_regex":
                        args["target_ip"] = TARGET_IP
                        args["port"] = TARGET_PORT

                    result = await session.call_tool(tool_name, args)

                    tool_output = result.content[0].text if result.content else "No output"
                    print(f"\n[Tool Output]: {tool_output[:200]}...")

                    # Important: We must append the tool output to the history so the LLM knows what happened.
                    # AND we must strip the hallucinated parts from the assistant's previous message if necessary,
                    # but usually just appending the tool output is enough if we force a stop.
                    
                    messages.append({
                        "role": "assistant", 
                        "content": json.dumps({"action": "call_tool", "tool": tool_name, "arguments": args})
                    })
                    
                    messages.append({
                        "role": "user", 
                        "content": f"Tool '{tool_name}' output:\n{tool_output}\n\nWhat is the next step?"
                    })

                    messages.append({
                        "role": "user",
                        "content": f"Tool result:\n{tool_output}"
                    })

                else:
                    print("Unexpected format from LLM.")
                    break


asyncio.run(main())
