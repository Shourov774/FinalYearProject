import React from "react";
import { useRef, useEffect } from "react";

import "../CSS/terminal.css";

export default function Terminal({logs,running,color="c"}){
  const ref = useRef();
  useEffect( () => { 
    if(ref.current)
      ref.current.scrollTop=ref.current.scrollHeight;
  },[logs]);

  const cls={ INFO:"li", OK:"lok", WARN:"lw", ERR:"le", DATA:"ld" };
  return(
    <>
      <div className="term-hd">
        <div className="dot r"/>
        <div className="dot y"/>
        <div className="dot g"/>
        <span>System log</span>
      </div>
      <div className="term attached" ref={ref}>
        {logs.length === 0 && <span className="li"> Awaiting command or there is some mistakes...</span>}
        {logs.map((l,i)=>(
          <div key={i} className="ll">
            <span className="lt"> {l.t} </span>
            <span className= {cls[l.k]||"li"} style= {{width:"40px"}} > [{l.k}] </span>
            <span style= {{color:"var(--txt)"}} > {l.m} </span>
          </div>
        ))}
        {running && <span className="cursor"/>}
      </div>
    </>
  );
}