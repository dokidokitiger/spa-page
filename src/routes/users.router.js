import express from 'express';
import { prisma } from '../utils/prisma.utils.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import authMiddleware from '../middlewares/auth.middleware.js';



const router = express.Router();
const ACCESS_TOKEN_SECRET_KEY = process.env.ACCESS_TOKEN_SECRET_KEY;
//사용자 회원가입 api 만들기!
router.post('/sign-up', async (req, res, next) => {
    // 1. **요청 정보**
    //     - **이메일, 비밀번호, 비밀번호 확인, 이름**을 **Request Body**(**`req.body`**)로 전달 받습니다.
    const { email, name, password, passwordConfirm } = req.body;
    // 2. **유효성 검증 및 에러 처리**
    //     - **회원 정보 중 하나라도 빠진 경우** - “OOO을 입력해 주세요.”
    //     - **이메일 형식에 맞지 않는 경우** - “이메일 형식이 올바르지 않습니다.”
    //     - **이메일이 중복되는 경우** - “이미 가입 된 사용자입니다.”
    //     - **비밀번호가 6자리 미만인 경우** - “비밀번호는 6자리 이상이어야 합니다.”
    //     - **비밀번호와 비밀번호 확인이 일치하지 않는 경우** - “입력 한 두 비밀번호가 일치하지 않습니다.”
    const isExistUser = await prisma.users.findFirst({
        where: {
            email,
        },
    });
    if (isExistUser) {
        return res.status(400).json({ message: '이미 가입된 사용자입니다.' });
    }
    if (password.length < 6)
        return res.status(400).json({ message: '비밀번호는 6자리 이상이어야 합니다.' });
    if (password !== passwordConfirm)
        return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    if (!email)
        return res.status(400).json({ message: '이메일을 입력하세요.' });
    if (!name)
        return res.status(400).json({ message: '이름을 입력하세요' });
    if (!password)
        return res.status(400).json({ message: '비밀번호를 입력해주세요' });
    if (!passwordConfirm)
        return res.status(400).json({ message: '비밀번호 확인을 입력해주세요' });

    // 3. **비즈니스 로직(데이터 처리)**
    //     - **사용자 ID, 역할, 생성일시, 수정일시**는 ****자동 생성됩니다.
    //     - **역할**의 종류는 다음과 같으며, 기본 값은 **`APPLICANT`** 입니다.
    //         - 지원자 **`APPLICANT`**
    //         - 채용 담당자 **`RECRUITER`**
    //     - 보안을 위해 **비밀번호**는 평문(Plain Text)으로 저장하지 않고 **Hash 된 값**을 저장합니다.
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.users.create({
        data: { email, password: hashedPassword, name },
    })
    const userInfo = await prisma.usersInfos.create({
        data: {
            UserId: user.userId,
            role: "APPLICANT",
        }
    })
    // 4. **반환 정보**
    //     - **사용자 ID, 이메일, 이름, 역할, 생성일시, 수정일시**를 반환합니다.
    return res.status(201).json({
        message: '회원가입이 완료되었습니다.', data: {
            id: user.userId, email: user.email, name: user.name, role: userInfo.role, createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        }
    })
});
    // 3. **비즈니스 로직(데이터 처리)**
    //     - **AccessToken(Payload**에 **`사용자 ID`**를 포함하고, **유효기한**이 **`12시간`)**을 생성합니다.
    // function createAccessToken(id) {
    //     const accessToken = jwt.sign(
    //       { id: id }, // JWT 데이터
    //       ACCESS_TOKEN_SECRET_KEY, // Access Token의 비밀 키
    //       { expiresIn: '12h' }, // Access Token이 10초 뒤에 만료되도록 설정합니다.
    //     );
      
    //     return accessToken;
    //   }
    function createAccessToken(id) {
        return jwt.sign(
            {id: id},
            ACCESS_TOKEN_SECRET_KEY,
            {expiresIn: '12h'},
        )
    }

//로그인 api
router.post('/sign-in', async (req, res, next) => {

    // 1. **요청 정보**
    //     - **이메일, 비밀번호**를 **Request Body**(**`req.body`**)로 전달 받습니다.
    const {email, password} = req.body;
    // 2. **유효성 검증 및 에러 처리**
    //     - **로그인 정보 중 하나라도 빠진 경우** - “OOO을 입력해 주세요.”
    //     - **이메일 형식에 맞지 않는 경우** - “이메일 형식이 올바르지 않습니다.”
    //     - **이메일로 조회되지 않거나 비밀번호가 일치하지 않는 경우** - “인증 정보가 유효하지 않습니다.”
    const user = await prisma.users.findFirst({where : {email}});
    if (!user)
        return res.status(401).json({message: '인증정보가 유효하지 않습니다.'})
    if(!email || !password)
        return res.status(401).json({message: '입력을 빠뜨린 칸이 있습니다.'});
    
    const accessToken = createAccessToken(user.userId);
    res.cookie('authorization', `Bearer ${accessToken}`);
    return res.status(200).json({message: '로그인 성공!', data: {accessToken}});
      
    // 4. **반환 정보**
    //     - **AccessToken**을 반환합니다.
});

//사용자 조회 API

router.get('/users', authMiddleware, async(req, res, next) => {
    try {
    const {userId} = req.user;
    const user = await prisma.users.findFirst({
        where: { userId: +userId},
        select: {
            userId:true,
            email: true,
            name: true,
            createdAt: true,
            updatedAt: true,
            usersInfos: {
                select: {
                    role:true,
                }
            }
        }
    });
    const resultdata = {
        userId: user.userId,
        email: user.email,
        name: user.name,
        role: user.usersInfos.role,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
    }
    return res.status(200).json({data: resultdata});
    } catch (error) {
        next(error);
    }
    
});

export default router;