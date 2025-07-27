import os
from dotenv import load_dotenv
load_dotenv()
import requests
import streamlit as st
from langchain_openai import ChatOpenAI
from langchain.agents import initialize_agent, AgentType
from langchain.tools import tool
from langchain.memory import ConversationBufferMemory
from datetime import datetime, timedelta
import json

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --------------------------
# Helper: Date parameters
# --------------------------
def _date_params():
    """Return pubStartDate and pubEndDate query params for the last 2 years."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=2*365)
    return {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT00:00:00.000")
    }

# --------------------------
# Tools (always return JSON)
# --------------------------
@tool("summarize_cve", return_direct=False)
def summarize_cve(cve_id: str) -> str:
    """Summarize the details of a specific CVE from the NVD database."""
    try:
        params = {"cveId": cve_id, **_date_params()}
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return json.dumps({"type": "error", "message": f"No details found for {cve_id} in the last 2 years."})

            cve_item = vulns[0]["cve"]
            description = cve_item.get("descriptions", [{}])[0].get("value", "No description available.")
            metrics = cve_item.get("metrics", {})
            severity, score = "N/A", "N/A"

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "N/A")
                score = cvss.get("baseScore", "N/A")

            return json.dumps({
                "type": "cve_summary",
                "cve_id": cve_id,
                "severity": severity,
                "score": score,
                "description": description
            })
        else:
            return json.dumps({"type": "error", "message": f"Error querying NVD API: {response.status_code}"})
    except Exception as e:
        return json.dumps({"type": "error", "message": f"Exception occurred: {e}"})


@tool("recent_cves_for_product", return_direct=False)
def recent_cves_for_product(product_name: str) -> str:
    """Get the most recent CVEs related to a product name from the NVD database."""
    try:
        params = {"keywordSearch": product_name,
                  "resultsPerPage": 5,
                  **_date_params()
                  }
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return json.dumps({
                    "type": "error",
                    "message": f"No recent CVEs found for product '{product_name}' in the last 2 years."
                })

            results = []
            for v in vulns:
                cve_id = v["cve"]["id"]
                desc = v["cve"]["descriptions"][0]["value"]
                results.append({"cve_id": cve_id, "description": desc})

            return json.dumps({
                "type": "product_cves",
                "product": product_name,
                "cves": results
            })
        else:
            return json.dumps({
                "type": "error",
                "message": f"Error querying NVD API: {response.status_code}: {response.text} \n {params}"
            })
    except Exception as e:
        print(params)
        return json.dumps({
            "type": "error",
            "message": f"Exception occurred: {e}"
        })

# --------------------------
# LangChain Agent with Memory
# --------------------------
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, api_key=os.getenv("OPENAI_KEY"))
memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
tools = [summarize_cve, recent_cves_for_product]

agent = initialize_agent(
    tools=tools,
    llm=llm,
    memory=memory,
    agent=AgentType.OPENAI_FUNCTIONS,
    verbose=True
)

# --------------------------
# Streamlit UI
# --------------------------
st.set_page_config(page_title="🛡️ CVE Intelligence Demo", page_icon="🛡️")
st.title("🛡️ CVE Intelligence Demo")
st.markdown("Ask me about **any CVE** or a **product's recent vulnerabilities**. (Results are filtered to the last **2 years**.)")

if "history" not in st.session_state:
    st.session_state.history = []

user_input = st.text_input("🔎 Your query:", placeholder="e.g. What is CVE-2023-21716? or Recent CVEs for OpenSSL")

if st.button("Ask") and user_input:
    with st.spinner("🔎 Thinking..."):
        result = agent.run(user_input)
        st.session_state.history.append((user_input, result))

# --------------------------
# Result Display (Rich)
# --------------------------
severity_color = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢"
}

for query, result in reversed(st.session_state.history):
    st.markdown(f"### ❓ {query}")

    # Try to parse JSON result
    try:
        parsed = json.loads(result)
    except:
        st.info(result)
        continue

    if parsed["type"] == "error":
        st.error(parsed["message"])

    elif parsed["type"] == "cve_summary":
        sev = parsed["severity"].upper()
        badge = severity_color.get(sev, "⚪")
        with st.expander(f"{badge} **{parsed['cve_id']}** (Severity: {parsed['severity']} | Score: {parsed['score']})", expanded=True):
            st.write(parsed["description"])

    elif parsed["type"] == "product_cves":
        st.markdown(f"### 🔍 Recent CVEs for **{parsed['product']}**")
        for cve in parsed["cves"]:
            with st.expander(f"**{cve['cve_id']}**"):
                st.write(cve["description"])
