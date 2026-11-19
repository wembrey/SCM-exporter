#!/usr/bin/env python3
"""Read-only Strata Cloud Manager auto-discovery and evidence exporter."""
from __future__ import annotations
import argparse, csv, hashlib, json, logging, os, re, time, shutil, zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

VERSION = "1.5.0"
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
API_BASE = "https://api.strata.paloaltonetworks.com"
DISCOVERY = {
    "folders": "/config/setup/v1/folders",
    "snippets": "/config/setup/v1/snippets",
    "devices": "/config/setup/v1/devices",
}
ENDPOINTS = {
    "addresses":"/config/objects/v1/addresses", "address-groups":"/config/objects/v1/address-groups",
    "services":"/config/objects/v1/services", "service-groups":"/config/objects/v1/service-groups",
    "tags":"/config/objects/v1/tags", "applications":"/config/objects/v1/applications",
    "application-groups":"/config/objects/v1/application-groups",
    "application-filters":"/config/objects/v1/application-filters", "schedules":"/config/objects/v1/schedules",
    "external-dynamic-lists":"/config/objects/v1/external-dynamic-lists",
    "security-rules":"/config/security/v1/security-rules", "nat-rules":"/config/network/v1/nat-rules",
    "decryption-rules":"/config/decryption/v1/decryption-rules",
    "authentication-rules":"/config/security/v1/authentication-rules",
    "antivirus-profiles":"/config/security/v1/anti-virus-profiles",
    "anti-spyware-profiles":"/config/security/v1/anti-spyware-profiles",
    "vulnerability-protection-profiles":"/config/security/v1/vulnerability-protection-profiles",
    "url-access-profiles":"/config/security/v1/url-access-profiles",
    "file-blocking-profiles":"/config/security/v1/file-blocking-profiles",
    "wildfire-profiles":"/config/security/v1/wildfire-anti-virus-profiles",
    "dns-security-profiles":"/config/security/v1/dns-security-profiles",
    "profile-groups":"/config/security/v1/profile-groups",
    "log-forwarding-profiles":"/config/logging/v1/log-forwarding-profiles",
    "zones":"/config/network/v1/zones", "ethernet-interfaces":"/config/network/v1/ethernet-interfaces",
    "aggregate-interfaces":"/config/network/v1/aggregate-interfaces",
    "loopback-interfaces":"/config/network/v1/loopback-interfaces",
    "tunnel-interfaces":"/config/network/v1/tunnel-interfaces", "vlan-interfaces":"/config/network/v1/vlan-interfaces",
    "virtual-routers":"/config/network/v1/virtual-routers", "static-routes":"/config/network/v1/static-routes",
    "ipsec-tunnels":"/config/network/v1/ipsec-tunnels", "ike-gateways":"/config/network/v1/ike-gateways",
    "ike-crypto-profiles":"/config/network/v1/ike-crypto-profiles",
    "ipsec-crypto-profiles":"/config/network/v1/ipsec-crypto-profiles",
    "dns-settings":"/config/device/v1/dns-settings", "ntp-settings":"/config/device/v1/ntp-settings",
    "system-settings":"/config/device/v1/system-settings", "administrators":"/config/device/v1/administrators",
    "authentication-profiles":"/config/identity/v1/authentication-profiles",
    "certificates":"/config/device/v1/certificates",
    "ha-devices":"/config/device/v1/ha-devices",
    "ha-configurations":"/config/device/v1/ha-configurations",
}
PRUNED_ENDPOINTS = {
    # Kept out of --auto-export because these are usually large/reference data or low-value
    # for LLD build validation. They remain selectable with --endpoint or --menu.
    "applications": "Large App-ID/reference dataset; policy already exposes referenced applications",
    "application-groups": "Potentially large; include when the LLD explicitly validates custom app groups",
    "application-filters": "Potentially large; include when the LLD explicitly validates application filters",
    "schedules": "Usually low-value for baseline build validation unless policy schedules are in scope",
    "external-dynamic-lists": "Optional; include when EDLs are part of the LLD",
}

AUTO_ENDPOINTS = [
    # Objects referenced by an LLD/build sheet
    "addresses", "address-groups", "services", "service-groups", "tags",
    # Policy
    "security-rules", "nat-rules", "decryption-rules",
    # Network / routing / VPN
    "zones", "ethernet-interfaces", "aggregate-interfaces", "loopback-interfaces",
    "tunnel-interfaces", "vlan-interfaces", "virtual-routers", "static-routes",
    "ipsec-tunnels", "ike-gateways", "ike-crypto-profiles", "ipsec-crypto-profiles",
    # Security / logging
    "antivirus-profiles", "anti-spyware-profiles", "vulnerability-protection-profiles",
    "url-access-profiles", "file-blocking-profiles", "wildfire-profiles", "profile-groups",
    "log-forwarding-profiles",
    # Device / identity settings useful for build validation
    "dns-settings", "ntp-settings", "system-settings", "authentication-profiles", "certificates",
    # HA inventory/configuration
    "ha-devices", "ha-configurations",
]

SYSTEM_SNIPPET = re.compile(r"^(predefined-snippet|default|optional-default|office365|proxy|rbi|saas-tenant-restrictions|Auto-VPN-|ZTP-|Internet-Access-|Web-Security-|Gen-AI-|app-tagging|hip-default|dlp-predefined|SAAS-Inline-|DNS-Best-|GlobalProtect-|AIRS-|GCP-VM-|Azure-VM-|AWS-VM-|vm-hsf-)", re.I)
SENSITIVE = re.compile(r"(password|passwd|secret|private[_-]?key|authorization|token)$", re.I)

@dataclass
class Result:
    name:str; path:str; scope_type:str; scope_name:str; status:str
    http_status:Optional[int]; records:int; pages:int
    raw_file:Optional[str]=None; csv_file:Optional[str]=None; sha256:Optional[str]=None; error:Optional[str]=None

class Client:
    def __init__(self, cid:str, secret:str, tsg:str, timeout:int, verify:bool, request_timeout:int=20, delay:float=0.10):
        self.cid, self.secret, self.tsg, self.timeout, self.verify = cid, secret, tsg, timeout, verify
        self.request_timeout, self.delay = request_timeout, delay
        self.token, self.expiry = None, 0.0
        self.s = requests.Session()
        retry=Retry(total=4, connect=4, read=4, status=4, backoff_factor=1,
                    status_forcelist=(408,429,502,503,504), allowed_methods=frozenset(("POST",)),
                    respect_retry_after_header=True, raise_on_status=False)
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
    def auth(self, force=False):
        if self.token and not force and time.time() < self.expiry-60: return self.token
        r=self.s.post(AUTH_URL, auth=(self.cid,self.secret),
          data={"grant_type":"client_credentials","scope":f"tsg_id:{self.tsg}"},
          headers={"Accept":"application/json","Content-Type":"application/x-www-form-urlencoded"},
          timeout=self.timeout, verify=self.verify)
        r.raise_for_status(); body=r.json(); self.token=body["access_token"]; self.expiry=time.time()+int(body.get("expires_in",900)); return self.token
    def get(self, path:str, params:Dict[str,Any]):
        url=path if path.startswith("http") else API_BASE+path
        r=self.s.get(url, params=params, headers={"Authorization":f"Bearer {self.auth()}","Accept":"application/json"}, timeout=self.request_timeout, verify=self.verify)
        if self.delay: time.sleep(self.delay)
        if r.status_code==401:
            r=self.s.get(url, params=params, headers={"Authorization":f"Bearer {self.auth(True)}","Accept":"application/json"}, timeout=self.request_timeout, verify=self.verify)
            if self.delay: time.sleep(self.delay)
        return r

def safe(s:str): return re.sub(r"[^A-Za-z0-9._-]+","_",s).strip("._") or "export"
def redact(v:Any, key=""):
    if SENSITIVE.search(key): return "[REDACTED]"
    if isinstance(v,dict): return {k:redact(x,str(k)) for k,x in v.items()}
    if isinstance(v,list): return [redact(x,key) for x in v]
    return v
def records(payload:Any):
    if isinstance(payload,list): return [x if isinstance(x,dict) else {"value":x} for x in payload]
    if isinstance(payload,dict):
        for k in ("data","items","results","resources","entries"):
            if isinstance(payload.get(k),list): return [x if isinstance(x,dict) else {"value":x} for x in payload[k]]
        if set(payload).issubset({"total","count","limit","offset","next","next_page","nextPageToken"}): return []
        return [payload]
    return [{"value":payload}]
def error_text(r):
    try: b=r.json()
    except ValueError: return r.text[:2000] or r.reason
    out=[]
    if isinstance(b,dict):
        for e in b.get("_errors",[]):
            if isinstance(e,dict): out.append(" | ".join(str(e[k]) for k in ("code","message","details","help") if e.get(k)))
        if b.get("_request_id"): out.append("request_id="+str(b["_request_id"]))
    return "; ".join(out) or json.dumps(b,ensure_ascii=False)[:2000]
def flatten(v:Any,p="",out=None):
    out={} if out is None else out
    if isinstance(v,dict):
        for k,x in v.items(): flatten(x,f"{p}.{k}" if p else str(k),out)
    elif isinstance(v,list): out[p]="; ".join(map(str,v)) if all(not isinstance(x,(dict,list)) for x in v) else json.dumps(v,ensure_ascii=False,separators=(",",":"))
    else: out[p or "value"]="" if v is None else str(v)
    return out
def write_rows(path:Path, rs:List[Dict[str,Any]], endpoint:str, scope:Dict[str,str]):
    st=next(iter(scope),"tenant"); sn=str(scope.get(st,"all")); now=datetime.now(timezone.utc).isoformat(); rows=[]; fields=[]; seen=set()
    for item in rs:
        row={"_scope_type":st,"_scope_name":sn,"_endpoint":endpoint,"_exported_at_utc":now,**flatten(item)}; rows.append(row)
        for k in row:
            if k not in seen: seen.add(k); fields.append(k)
    base=["_scope_type","_scope_name","_endpoint","_exported_at_utc"]
    fields=base+[x for x in fields if x not in base]
    with path.open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
def export(client,name,path,scope,raw_dir,csv_dir,limit,max_pages):
    st=next(iter(scope),"tenant"); sn=str(scope.get(st,"all")); allr=[]; pages=[]; offset=0; status=None
    try:
        for _ in range(max_pages):
            r=client.get(path,{**scope,"limit":limit,"offset":offset}); status=r.status_code
            if status in (403,404): return Result(name,path,st,sn,"skipped",status,0,len(pages),error=f"HTTP {status}: {error_text(r)}")
            if status>=400: raise RuntimeError(f"HTTP {status}: {error_text(r)}")
            body=redact(r.json()); batch=records(body); allr.extend(batch); pages.append(body)
            total=body.get("total") if isinstance(body,dict) else None
            if not isinstance(total,int) or offset+len(batch)>=total or not batch: break
            offset+=len(batch)
        else: raise RuntimeError(f"Pagination exceeded max_pages={max_pages}")
        rp=raw_dir/(safe(name)+".json"); cp=csv_dir/(safe(name)+".csv")
        doc={"endpoint":name,"api_path":path,"scope":scope,"exported_at_utc":datetime.now(timezone.utc).isoformat(),"record_count":len(allr),"pages":pages}
        text=json.dumps(doc,indent=2,ensure_ascii=False); rp.write_text(text,encoding="utf-8"); write_rows(cp,allr,name,scope)
        return Result(name,path,st,sn,"success",status,len(allr),len(pages),str(rp),str(cp),hashlib.sha256(text.encode()).hexdigest())
    except requests.Timeout as e:
        return Result(name,path,st,sn,"timeout",status,len(allr),len(pages),error=f"request timeout: {e}")
    except (requests.RequestException,ValueError,RuntimeError) as e:
        return Result(name,path,st,sn,"failed",status,len(allr),len(pages),error=str(e))
def discover(client,raw,csvd,limit,max_pages):
    results=[]; scopes=[]
    for plural,path in DISCOVERY.items():
        r=export(client,"discovery-"+plural,path,{},raw,csvd,limit,max_pages); results.append(r)
        if r.status!="success" or not r.raw_file: continue
        doc=json.loads(Path(r.raw_file).read_text())
        singular={"folders":"folder","snippets":"snippet","devices":"device"}[plural]
        for page in doc["pages"]:
            for item in records(page):
                n=item.get("name") or item.get("display_name") or item.get("hostname") or item.get("id")
                if n: scopes.append({"scope_type":singular,"scope_name":str(n),"id":str(item.get("id","")),"parent":str(item.get("parent",item.get("parent_id","")))})
    return results,scopes
def write_dicts(path,rows,fields):
    with path.open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
def consolidate(csv_dir,out):
    sources=[p for p in sorted(csv_dir.glob("*.csv")) if not p.name.startswith("discovery-")]; fields=[]; seen=set(); rows=[]
    for p in sources:
        with p.open(newline="",encoding="utf-8-sig") as f:
            reader=csv.DictReader(f)
            for x in reader.fieldnames or []:
                if x not in seen: seen.add(x); fields.append(x)
            rows.extend(dict(x) for x in reader)
    fields=fields or ["_scope_type","_scope_name","_endpoint","_exported_at_utc"]
    write_dicts(out,rows,fields); return len(rows)


def excel_col(n:int) -> str:
    out=""
    while n:
        n, rem = divmod(n-1, 26); out=chr(65+rem)+out
    return out


def clean_cell(value:Any) -> str:
    text="" if value is None else str(value)
    # XML 1.0 does not permit most control characters.
    return "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 32)


def unique_sheet_name(name:str, used:set) -> str:
    name=re.sub(r"[\\/*?:\[\]]", "_", name)[:31] or "Sheet"
    base=name; i=2
    while name.lower() in used:
        suffix=f"_{i}"; name=base[:31-len(suffix)]+suffix; i+=1
    used.add(name.lower()); return name


def sheet_xml(headers:List[str], rows:List[Dict[str,Any]]) -> str:
    columns=headers or ["Result"]
    matrix=[columns]+[[clean_cell(row.get(h,"")) for h in columns] for row in rows]
    last_col=excel_col(len(columns)); last_row=max(1,len(matrix))
    parts=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
      '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
      f'<dimension ref="A1:{last_col}{last_row}"/>',
      '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>',
      '<sheetFormatPr defaultRowHeight="15"/>', '<sheetData>']
    for r_idx,row in enumerate(matrix,1):
        parts.append(f'<row r="{r_idx}">')
        for c_idx,value in enumerate(row,1):
            ref=f"{excel_col(c_idx)}{r_idx}"; style=' s="1"' if r_idx==1 else ''
            preserve=' xml:space="preserve"' if value.startswith(" ") or value.endswith(" ") or "\n" in value else ''
            parts.append(f'<c r="{ref}" t="inlineStr"{style}><is><t{preserve}>{xml_escape(value)}</t></is></c>')
        parts.append('</row>')
    parts.append('</sheetData>')
    if rows: parts.append(f'<autoFilter ref="A1:{last_col}{last_row}"/>')
    parts.append('</worksheet>')
    return ''.join(parts)


def build_workbook(path:Path, manifest:Dict[str,Any], scopes:List[Dict[str,str]],
                   selected_scopes:List[Dict[str,str]], results:List[Result], endpoints:List[str]) -> None:
    """Create one dependency-free XLSX with summary, inventory, API results and resource tabs."""
    summary=manifest["summary"]
    sheets=[]
    sheets.append(("Summary", ["Property","Value"], [
      {"Property":"Exporter version","Value":manifest["exporter_version"]},
      {"Property":"Exported UTC","Value":manifest["exported_at_utc"]},
      {"Property":"TSG ID","Value":manifest["tsg_id"]},
      {"Property":"Successful queries","Value":summary["success"]},
      {"Property":"Skipped queries","Value":summary["skipped"]},
      {"Property":"Timed-out queries","Value":summary["timeout"]},
      {"Property":"Failed queries","Value":summary["failed"]},
      {"Property":"Configuration records","Value":summary["records"]},
      {"Property":"Discovered scopes","Value":summary["discovered_scopes"]},
      {"Property":"Selected scopes","Value":summary["selected_scopes"]},
      {"Property":"Read only","Value":"Yes"},
    ]))
    inventory=[]
    selected_keys={(x["scope_type"],x["scope_name"]) for x in selected_scopes}
    for x in scopes:
        inventory.append({**x,"selected":"Yes" if (x["scope_type"],x["scope_name"]) in selected_keys else "No"})
    sheets.append(("Tenant Scopes",["scope_type","scope_name","id","parent","selected"],inventory))
    pruned_rows=[{"endpoint":n,"reason":reason,"included_this_run":"Yes" if n in endpoints else "No"} for n,reason in PRUNED_ENDPOINTS.items()]
    sheets.append(("Excluded Options",["endpoint","reason","included_this_run"],pruned_rows))
    result_rows=[]
    grouped={ep:[] for ep in endpoints}
    for r in results:
        resource=next((ep for ep in sorted(endpoints,key=len,reverse=True) if r.name.endswith("-"+ep)), r.name)
        result_rows.append({"resource":resource,**asdict(r)})
        if r.status=="success" and r.csv_file and resource in grouped:
            with open(r.csv_file,newline="",encoding="utf-8-sig") as f:
                grouped[resource].extend(dict(x) for x in csv.DictReader(f))
    result_headers=[]
    for row in result_rows:
        for k in row:
            if k not in result_headers: result_headers.append(k)
    sheets.append(("API Results",result_headers,result_rows))
    for ep in endpoints:
        rows=grouped.get(ep,[]); headers=[]
        for row in rows:
            for k in row:
                if k not in headers: headers.append(k)
        if not headers: headers=["_scope_type","_scope_name","_endpoint","_exported_at_utc","Result"]
        sheets.append((ep,headers,rows))

    used=set(); final=[]
    for name,headers,rows in sheets: final.append((unique_sheet_name(name,used),headers,rows))
    content_types=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
      '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
      '<Default Extension="xml" ContentType="application/xml"/>',
      '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
      '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    for i in range(1,len(final)+1): content_types.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    content_types.append('</Types>')
    wb_sheets=''.join(f'<sheet name="{xml_escape(n)}" sheetId="{i}" r:id="rId{i}"/>' for i,(n,_,_) in enumerate(final,1))
    workbook='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'+wb_sheets+'</sheets></workbook>'
    wb_rels=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for i in range(1,len(final)+1): wb_rels.append(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>')
    wb_rels.append(f'<Relationship Id="rId{len(final)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    root_rels='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    styles='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs></styleSheet>'
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml',''.join(content_types)); z.writestr('_rels/.rels',root_rels)
        z.writestr('xl/workbook.xml',workbook); z.writestr('xl/_rels/workbook.xml.rels',''.join(wb_rels)); z.writestr('xl/styles.xml',styles)
        for i,(_,headers,rows) in enumerate(final,1): z.writestr(f'xl/worksheets/sheet{i}.xml',sheet_xml(headers,rows))



def choose_endpoints_interactively(defaults:List[str]) -> List[str]:
    """Let the operator opt pruned/optional endpoints back into this run."""
    print("\nDefault auto-export endpoints:")
    print("  " + ", ".join(defaults))
    optional=[x for x in PRUNED_ENDPOINTS if x in ENDPOINTS]
    if not optional:
        return defaults
    print("\nExcluded by default (optional):")
    for i,name in enumerate(optional,1):
        print(f"  {i:2}. {name:24} {PRUNED_ENDPOINTS[name]}")
    print("\nEnter comma-separated numbers/names to include, 'all', or press Enter for defaults only.")
    answer=input("Optional endpoints> ").strip()
    if not answer:
        return list(defaults)
    if answer.lower()=="all":
        return list(dict.fromkeys(defaults+optional))
    chosen=[]
    for part in [x.strip() for x in answer.split(",") if x.strip()]:
        if part.isdigit() and 1 <= int(part) <= len(optional): chosen.append(optional[int(part)-1])
        elif part in optional: chosen.append(part)
        else: print(f"Ignoring unknown optional selection: {part}")
    return list(dict.fromkeys(defaults+chosen))


def main():
    ap=argparse.ArgumentParser(description="SCM read-only discovery and full evidence exporter")
    ap.add_argument("--output",default="./scm-export"); ap.add_argument("--discover",action="store_true")
    ap.add_argument("--auto-export",action="store_true"); ap.add_argument("--include-system-scopes",action="store_true")
    ap.add_argument("--scope-regex"); ap.add_argument("--scope-type",action="append",choices=("folder","snippet","device"))
    ap.add_argument("--endpoint",action="append",dest="endpoints")
    ap.add_argument("--list-endpoints",action="store_true")
    ap.add_argument("--list-pruned",action="store_true",help="Show endpoints excluded from auto-export and why")
    ap.add_argument("--menu",action="store_true",help="Interactively opt excluded endpoints into auto-export")
    ap.add_argument("--page-size",type=int,default=200); ap.add_argument("--max-pages",type=int,default=1000)
    ap.add_argument("--timeout",type=int,default=60,help="OAuth/authentication timeout in seconds")
    ap.add_argument("--request-timeout",type=int,default=20,help="Per SCM GET timeout in seconds (default: 20)")
    ap.add_argument("--delay",type=float,default=0.10,help="Delay between GET requests in seconds (default: 0.10)")
    ap.add_argument("--insecure",action="store_true"); ap.add_argument("--verbose",action="store_true")
    a=ap.parse_args(); logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    if a.list_endpoints:
        for n,p in sorted(ENDPOINTS.items()): print(f"{n:40} {p}")
        return 0
    if a.list_pruned:
        for n,reason in PRUNED_ENDPOINTS.items(): print(f"{n:28} {reason}")
        return 0
    if not (a.discover or a.auto_export): ap.error("Specify --discover or --auto-export")
    selected=a.endpoints or (AUTO_ENDPOINTS if a.auto_export else list(ENDPOINTS))
    if a.menu:
        if not a.auto_export: ap.error("--menu requires --auto-export")
        if a.endpoints: ap.error("Use either --menu or explicit --endpoint options, not both")
        selected=choose_endpoints_interactively(list(AUTO_ENDPOINTS))
    unknown=set(selected)-set(ENDPOINTS)
    if unknown: ap.error("Unknown endpoint(s): "+", ".join(sorted(unknown)))
    creds=[os.getenv("SCM_CLIENT_ID"),os.getenv("SCM_CLIENT_SECRET"),os.getenv("SCM_TSG_ID")]
    if not all(creds): ap.error("Set SCM_CLIENT_ID, SCM_CLIENT_SECRET and SCM_TSG_ID")
    root=Path(a.output).expanduser().resolve()/datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"); raw=root/"raw-json"; csvd=root/"evidence-csv"; raw.mkdir(parents=True); csvd.mkdir()
    c=Client(*creds,a.timeout,not a.insecure,request_timeout=a.request_timeout,delay=a.delay)
    try: c.auth()
    except requests.RequestException as e: logging.error("Authentication failed: %s",e); return 2
    logging.info("Discovering tenant folders, snippets and devices")
    results,scopes=discover(c,raw,csvd,a.page_size,a.max_pages)
    write_dicts(root/"discovered-scopes.csv",scopes,["scope_type","scope_name","id","parent"])
    chosen=list(scopes)
    if not a.include_system_scopes: chosen=[x for x in chosen if not (x["scope_type"]=="snippet" and SYSTEM_SNIPPET.search(x["scope_name"]))]
    if a.scope_regex:
        rx=re.compile(a.scope_regex,re.I); chosen=[x for x in chosen if rx.search(x["scope_name"])]
    if a.scope_type: chosen=[x for x in chosen if x["scope_type"] in set(a.scope_type)]
    write_dicts(root/"selected-scopes.csv",chosen,["scope_type","scope_name","id","parent"])
    for x in scopes: print(f"{x['scope_type']:8} {x['scope_name']}")
    if a.auto_export:
        jobs=[(x,n) for x in chosen for n in selected]; total=len(jobs)
        for i,(x,n) in enumerate(jobs,1):
            scope={x["scope_type"]:x["scope_name"]}; job=f"{x['scope_type']}-{safe(x['scope_name'])}-{n}"
            logging.info("[%d/%d] %s",i,total,job); r=export(c,job,ENDPOINTS[n],scope,raw,csvd,a.page_size,a.max_pages); results.append(r)
            logging.info("%s: %s (%d records)",job,r.status,r.records)
    manifest={"exporter_version":VERSION,"exported_at_utc":datetime.now(timezone.utc).isoformat(),"api_base":API_BASE,"tsg_id":creds[2],"read_only":True,"discovered_scopes":scopes,"selected_scopes":chosen,"selected_endpoints":selected,"pruned_endpoints":PRUNED_ENDPOINTS,"results":[asdict(x) for x in results]}
    manifest["summary"]={"success":sum(x.status=="success" for x in results),"skipped":sum(x.status=="skipped" for x in results),"timeout":sum(x.status=="timeout" for x in results),"failed":sum(x.status=="failed" for x in results),"records":sum(x.records for x in results),"discovered_scopes":len(scopes),"selected_scopes":len(chosen)}
    final_path=Path(a.output).expanduser().resolve()/f"SCM_Evidence_{root.name}.xlsx"
    build_workbook(final_path,manifest,scopes,chosen,results,selected)
    shutil.rmtree(root)
    print(json.dumps(manifest["summary"],indent=2)); print("Workbook written to:",final_path)
    return 1 if (manifest["summary"]["failed"] or manifest["summary"]["timeout"]) else 0
if __name__=="__main__": raise SystemExit(main())
