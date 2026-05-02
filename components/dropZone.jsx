import React from "react";
import { useState } from "react";

import { fmtB } from "../cryotoFunction";
import "../CSS/dropzone.css";

export default function DropZone({file,onChange}){
  const [drag,setDrag]=useState(false);
  return(
    <div
      className={`dropzone ${drag?"drag":""} ${file?"has":""}`}
      onDragOver={e=>{
        e.preventDefault();
        setDrag(true)}
      }
      onDragLeave={()=>setDrag(false)}
      onDrop={e=>{
        e.preventDefault();
        setDrag(false);
        if(e.dataTransfer.files[0])onChange(e.dataTransfer.files[0])
        }
      }
    >
      {/* <input type="text" placeholder="Paste file path here..." onChange={e=>{if(e.target.value)onChange(e.target.value)}}/> */}
      <input type="file" onChange={e=>{if(e.target.files[0])onChange(e.target.files[0])}}/>
      {file?(
        <>
          <div className="drop-ico">📄</div>
          <div className="drop-ttl" style={{color:"var(--green)"}}>{file.name}</div>
          <div className="drop-sub">{fmtB(file.size)} · Click to change</div>
        </>
      ):(
        <>
          <div className="drop-ico">📁</div>
          <div className="drop-ttl">Drop any file here</div>
          <div className="drop-sub">PDF | DOCX | JPG | PNG | TXT | MP4 | ZIP</div>
        </>
      )}
    </div>
  );
}