각 소셜 인가 서버에 따라 스팩이 다르다 
그리고 폼 로그인 기능도 함께 사용하는 경우도있다 
이 모든 경우를 ProviderUser로 추상화 시켜

OAuth2UserService 가
providerUserConverter 를 통해 회원 등록해버린다 

이러한 설계를 통해 
확장성을 높일 수 있었다.


![asjlikdfjkdsa2134](https://github.com/user-attachments/assets/c406268e-a6d0-42e9-b773-eab688b6a825)
