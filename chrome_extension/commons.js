export function timeLog(msg){
  let current = new Date();
  let currentTime  = current.toLocaleTimeString();
  console.log(`[${currentTime}]${msg}`);
}