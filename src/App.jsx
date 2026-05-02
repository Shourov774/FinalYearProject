import React from "react";
import { useState, useRef, useCallback, useEffect } from "react";

import Encrypt from "../../pages/encrypt";
import Decrypt from "../../pages/decrypt";
import Attack from "../../pages/attack";
import Architecture from "../../pages/architecture";
import Report from "../../pages/report";
import "./App.css";


const TABS=[
  {id:"enc",label:"Encrypt",icon:"🔒",color:"c-cyan",section:"DEMO"},
  {id:"dec",label:"Decrypt",icon:"🔓",color:"c-cyan",section:null},
  {id:"attack",label:"Attacks",icon:"⚔️",color:"c-red",section:"ANALYSIS"},
  {id:"arch",label:"Architecture",icon:"📐",color:"c-purple",section:"DOCS"},
  {id:"report",label:"Full Report",icon:"📄",color:"c-green",section:null},
];

export default function App(){
  const [tab,setTab]=useState("enc");
  const active=TABS.find(t=>t.id===tab);

  const panels={enc:<Encrypt/>,dec:<Decrypt/>,attack:<Attack/>,arch:<Architecture/>,report:<Report/>};

  let lastSection=null;
  return(
    <>
      <div className="shell">
        <div className="sidebar">
          <div className="brand">
            <div className="brand-title">🔐 HybridCrypt</div>
            <div className="brand-sub">Secure File Transfer</div>
            <div className="brand-tag">● SYSTEM ONLINE</div>
          </div>
          <div className="nav">
            {TABS.map(t=>{
              const showSection=t.section&&t.section!==lastSection;
              if(t.section)lastSection=t.section;
              return(
                <div key={t.id}>
                  {showSection&&<div className="nav-section">{t.section}</div>}
                  <button className={`nav-item ${tab===t.id?`active ${t.color}`:""}`} onClick={()=>setTab(t.id)}>
                    <span className="nav-icon">{t.icon}</span>
                    <span>{t.label}</span>
                  </button>
                </div>
              );
            })}
          </div>
          <div className="sidebar-footer">
            <div style={{color:"var(--txt)",fontWeight:700,marginBottom:6, fontSize:12}}>Farhad Hasan Shourov</div>
            <div>ID: 2110579123</div>
            <div>EEE Department, RU</div>
            <div style={{marginTop:5,color:"var(--border2)"}}>─────────</div>
            <div style={{marginTop:5}}>AES-256-GCM</div>
            <div>RSA-OAEP | HMAC</div>
            <div>SHA-256</div>
          </div>
        </div>
        <div className="main">{panels[tab]}</div>
      </div>
    </>
  );
}
