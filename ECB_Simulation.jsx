import React from "react";

import { genAES,genRSA,aesEnc,aesDec,rsaEnc,rsaDec,exportRaw,importAES,hmacSign,hmacVerify,sha256,toHex,toB64,fmtB,sleep,now,readFile } from "./cryotoFunction"

export default async function EcbEncSimulate(data){
          // Simulate ECB by encrypting 16-byte blocks with same fixed key derivation
          const cry = window.crypto.subtle;
          const blockSize=16;
          const key=await cry.importKey("raw",new Uint8Array(32),{name:"AES-CBC"},false,["encrypt"]);
          const zeroIV=new Uint8Array(16);
          const blocks=[];
          const padded=data.byteLength%blockSize===0?data:new Uint8Array([...new Uint8Array(data),...new Array(blockSize-data.byteLength%blockSize).fill(0)]);
          for(let i=0;i<padded.byteLength;i+=blockSize){
            const block=padded.slice(i,i+blockSize);
            const enc=await cry.encrypt({name:"AES-CBC",iv:zeroIV},key,block);
            blocks.push(...new Uint8Array(enc).slice(0,blockSize));
          }
          return new Uint8Array(blocks);
        }
        