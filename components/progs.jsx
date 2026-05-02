import React from "react";

import "../CSS/progs.css";

export default function Prog({val,color="c",label}){
return(
    <div style={{marginBottom:12}}>
      <div className="prog-bg">
        <div className={`prog-fill ${color}`} style={{width:`${val}%`}}/>
      </div>
        <div className="prog-lbl">
          <span>{label}</span>
          <span>{val}%</span>
        </div>
    </div>
  );
}